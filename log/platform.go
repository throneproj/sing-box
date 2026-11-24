package log

type PlatformWriter interface {
	WriteMessage(level Level, message string)
}

// LeveledPlatformWriter is a PlatformWriter that reports the most verbose level it keeps, so the factory does not
// format lines it would drop. A writer without it takes every level.
type LeveledPlatformWriter interface {
	PlatformWriter
	LogLevel() Level
}

func platformWriterWants(writer PlatformWriter, level Level) bool {
	leveled, isLeveled := writer.(LeveledPlatformWriter)
	return !isLeveled || level <= leveled.LogLevel()
}
