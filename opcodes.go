package main

type FragmentType int

const (
	None      FragmentType = iota
	Call                   = 1
	Notify                 = 2
	Return                 = 3
	Echo                   = 4
	FrameUp                = 5
	FrameDown              = 6
)

type Opcode int

const (
	SyncNearEntities  Opcode = 0x00000006
	SyncContainerData        = 0x00000015
	SyncServerTime           = 0x0000002b
	SyncToMeDeltaInfo        = 0x0000002e
	SyncNearDeltaInfo        = 0x0000002d
)
