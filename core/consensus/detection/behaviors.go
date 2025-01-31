// consensus/detection/behaviors.go
package detection

type ValidatorBehavior struct {
	DoubleSignings    int
	MissedBlocks      int
	InvalidBlocks     int
	LastActiveBlock   int32
	ConsecutiveMisses int
}

// Helper methods for ValidatorBehavior
func (b *ValidatorBehavior) UpdateMissedBlock() {
	b.MissedBlocks++
	b.ConsecutiveMisses++
}

func (b *ValidatorBehavior) ResetConsecutiveMisses() {
	b.ConsecutiveMisses = 0
}
