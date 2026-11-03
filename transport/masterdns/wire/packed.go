package wire

import "iter"

const PackedBlockSize = 7

type PackedBlock struct {
	Type           uint8
	StreamID       uint16
	SequenceNum    uint16
	FragmentID     uint8
	TotalFragments uint8
}

func AppendPackedBlock(dst []byte, block PackedBlock) []byte {
	return append(dst,
		block.Type,
		byte(block.StreamID>>8), byte(block.StreamID),
		byte(block.SequenceNum>>8), byte(block.SequenceNum),
		block.FragmentID,
		block.TotalFragments,
	)
}

// PackedBlocks iterates the blocks of a PACKED_CONTROL_BLOCKS payload; a trailing partial block is ignored.
func PackedBlocks(payload []byte) iter.Seq[PackedBlock] {
	return func(yield func(PackedBlock) bool) {
		for offset := 0; offset+PackedBlockSize <= len(payload); offset += PackedBlockSize {
			block := PackedBlock{
				Type:           payload[offset],
				StreamID:       uint16(payload[offset+1])<<8 | uint16(payload[offset+2]),
				SequenceNum:    uint16(payload[offset+3])<<8 | uint16(payload[offset+4]),
				FragmentID:     payload[offset+5],
				TotalFragments: payload[offset+6],
			}
			if !yield(block) {
				return
			}
		}
	}
}

// Packet expands a block into the packet the reference handlers see, inheriting the session fields of its carrier.
func (b PackedBlock) Packet(carrier Packet) Packet {
	return Packet{
		SessionID:      carrier.SessionID,
		Type:           b.Type,
		SessionCookie:  carrier.SessionCookie,
		StreamID:       b.StreamID,
		SequenceNum:    b.SequenceNum,
		FragmentID:     b.FragmentID,
		TotalFragments: b.TotalFragments,
	}
}

// MaxPackedBlocks is how many blocks fit in percent of mtu, capped by absoluteMax and at least one.
func MaxPackedBlocks(mtu int, percent int, absoluteMax int) int {
	mtu = max(mtu, 1)
	percent = max(percent, 30)
	return max(min(max(mtu*percent/100/PackedBlockSize, 1), absoluteMax), 1)
}
