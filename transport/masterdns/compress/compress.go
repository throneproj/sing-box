package compress

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"io"
	"sync"

	E "github.com/sagernet/sing/common/exceptions"

	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
)

type Type uint8

const (
	Off Type = iota
	ZSTD
	LZ4
	ZLIB
)

const (
	DefaultMinSize      = 100
	MaxDecompressedSize = 10 << 20
)

var ErrTooLarge = E.New("decompressed payload exceeds safety limit")

var (
	zstdEncoder = sync.OnceValues(func() (*zstd.Encoder, error) {
		return zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest))
	})
	zstdDecoder = sync.OnceValues(func() (*zstd.Decoder, error) {
		return zstd.NewReader(nil, zstd.WithDecoderMaxMemory(MaxDecompressedSize))
	})
	flateWriterPool = sync.Pool{
		New: func() any {
			writer, _ := flate.NewWriter(nil, flate.BestSpeed)
			return writer
		},
	}
	flateReaderPool = sync.Pool{
		New: func() any {
			return flate.NewReader(bytes.NewReader(nil))
		},
	}
)

func ParseType(name string) (Type, error) {
	switch name {
	case "", "off":
		return Off, nil
	case "zstd":
		return ZSTD, nil
	case "lz4":
		return LZ4, nil
	case "zlib":
		return ZLIB, nil
	default:
		return Off, E.New("unknown compression: ", name)
	}
}

func (t Type) String() string {
	switch Normalize(uint8(t)) {
	case ZSTD:
		return "zstd"
	case LZ4:
		return "lz4"
	case ZLIB:
		return "zlib"
	default:
		return "off"
	}
}

func Normalize(value uint8) Type {
	if value > uint8(ZLIB) {
		return Off
	}
	return Type(value)
}

func PackPair(upload Type, download Type) uint8 {
	return uint8(Normalize(uint8(upload)))<<4 | uint8(Normalize(uint8(download)))
}

func SplitPair(value uint8) (upload Type, download Type) {
	return Normalize(value >> 4), Normalize(value & 0x0F)
}

// ForMTU turns compression off for a direction whose synced MTU cannot carry a payload above the minimum size.
func ForMTU(t Type, mtu int, minSize int) Type {
	if minSize <= 0 {
		minSize = DefaultMinSize
	}
	if mtu > 0 && (mtu < 100 || mtu <= minSize) {
		return Off
	}
	return Normalize(uint8(t))
}

func Compress(data []byte, t Type, minSize int) ([]byte, Type) {
	t = Normalize(uint8(t))
	if len(data) == 0 || t == Off {
		return data, Off
	}
	if minSize <= 0 {
		minSize = DefaultMinSize
	}
	if len(data) <= minSize {
		return data, Off
	}
	var (
		compressed []byte
		err        error
	)
	switch t {
	case ZSTD:
		compressed, err = compressZSTD(data)
	case LZ4:
		compressed, err = compressLZ4(data)
	case ZLIB:
		compressed, err = compressFlate(data)
	}
	if err != nil || len(compressed) >= len(data) {
		return data, Off
	}
	return compressed, t
}

func Decompress(data []byte, t Type) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}
	switch Normalize(uint8(t)) {
	case ZSTD:
		return decompressZSTD(data)
	case LZ4:
		return decompressLZ4(data)
	case ZLIB:
		return decompressFlate(data)
	default:
		return data, nil
	}
}

func compressZSTD(data []byte) ([]byte, error) {
	encoder, err := zstdEncoder()
	if err != nil {
		return nil, err
	}
	return encoder.EncodeAll(data, nil), nil
}

func decompressZSTD(data []byte) ([]byte, error) {
	decoder, err := zstdDecoder()
	if err != nil {
		return nil, err
	}
	output, err := decoder.DecodeAll(data, nil)
	if err != nil {
		return nil, err
	}
	if len(output) > MaxDecompressedSize {
		return nil, ErrTooLarge
	}
	return output, nil
}

func compressLZ4(data []byte) ([]byte, error) {
	output := make([]byte, 4+lz4.CompressBlockBound(len(data)))
	binary.LittleEndian.PutUint32(output, uint32(len(data)))
	n, err := lz4.CompressBlock(data, output[4:], nil)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, io.ErrShortBuffer
	}
	return output[:4+n], nil
}

func decompressLZ4(data []byte) ([]byte, error) {
	if len(data) < 4 {
		return nil, io.ErrUnexpectedEOF
	}
	size := binary.LittleEndian.Uint32(data)
	if size > MaxDecompressedSize {
		return nil, ErrTooLarge
	}
	output := make([]byte, size)
	n, err := lz4.UncompressBlock(data[4:], output)
	if err != nil {
		return nil, err
	}
	if uint32(n) != size {
		return nil, io.ErrUnexpectedEOF
	}
	return output, nil
}

func compressFlate(data []byte) ([]byte, error) {
	var output bytes.Buffer
	writer := flateWriterPool.Get().(*flate.Writer)
	defer flateWriterPool.Put(writer)
	writer.Reset(&output)
	_, err := writer.Write(data)
	if err == nil {
		err = writer.Close()
	}
	if err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func decompressFlate(data []byte) ([]byte, error) {
	input := bytes.NewReader(data)
	reader := flateReaderPool.Get().(io.ReadCloser)
	defer flateReaderPool.Put(reader)
	err := reader.(flate.Resetter).Reset(input, nil)
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	_, err = io.Copy(&output, io.LimitReader(reader, MaxDecompressedSize+1))
	reader.Close()
	// Trailing bytes after the final DEFLATE block make the payload invalid, as in the reference.
	if err != nil || input.Len() != 0 {
		return nil, io.ErrUnexpectedEOF
	}
	if output.Len() > MaxDecompressedSize {
		return nil, ErrTooLarge
	}
	return output.Bytes(), nil
}
