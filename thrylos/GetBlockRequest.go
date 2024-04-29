// Code generated by the FlatBuffers compiler. DO NOT EDIT.

package thrylos

import (
	flatbuffers "github.com/google/flatbuffers/go"
)

type GetBlockRequest struct {
	_tab flatbuffers.Table
}

func GetRootAsGetBlockRequest(buf []byte, offset flatbuffers.UOffsetT) *GetBlockRequest {
	n := flatbuffers.GetUOffsetT(buf[offset:])
	x := &GetBlockRequest{}
	x.Init(buf, n+offset)
	return x
}

func FinishGetBlockRequestBuffer(builder *flatbuffers.Builder, offset flatbuffers.UOffsetT) {
	builder.Finish(offset)
}

func GetSizePrefixedRootAsGetBlockRequest(buf []byte, offset flatbuffers.UOffsetT) *GetBlockRequest {
	n := flatbuffers.GetUOffsetT(buf[offset+flatbuffers.SizeUint32:])
	x := &GetBlockRequest{}
	x.Init(buf, n+offset+flatbuffers.SizeUint32)
	return x
}

func FinishSizePrefixedGetBlockRequestBuffer(builder *flatbuffers.Builder, offset flatbuffers.UOffsetT) {
	builder.FinishSizePrefixed(offset)
}

func (rcv *GetBlockRequest) Init(buf []byte, i flatbuffers.UOffsetT) {
	rcv._tab.Bytes = buf
	rcv._tab.Pos = i
}

func (rcv *GetBlockRequest) Table() flatbuffers.Table {
	return rcv._tab
}

func (rcv *GetBlockRequest) Id() int32 {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(4))
	if o != 0 {
		return rcv._tab.GetInt32(o + rcv._tab.Pos)
	}
	return 0
}

func (rcv *GetBlockRequest) MutateId(n int32) bool {
	return rcv._tab.MutateInt32Slot(4, n)
}

func GetBlockRequestStart(builder *flatbuffers.Builder) {
	builder.StartObject(1)
}
func GetBlockRequestAddId(builder *flatbuffers.Builder, id int32) {
	builder.PrependInt32Slot(0, id, 0)
}
func GetBlockRequestEnd(builder *flatbuffers.Builder) flatbuffers.UOffsetT {
	return builder.EndObject()
}