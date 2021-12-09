// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"context"

	"github.com/awcullen/opcua/ua"
)

// HistoryReadWriter provides methods to read and write historical data.
type HistoryReadWriter interface {
	HistoryReader
	HistoryWriter
}

// HistoryWriter provides methods to write historical data.
type HistoryWriter interface {

	// WriteEvent writes the event to storage. Implementation records object nodeId
	// and event fields (provided as slice of Variants). Implementation may check
	// context for timeout.
	WriteEvent(ctx context.Context, nodeID ua.NodeID, eventFields []ua.Variant) error

	// WriteValue writes the value to storage. Implementation records variable nodeId
	// and DataValue (a struct of value, quality and source timestamp). Implementation
	// may check context for timeout.
	WriteValue(ctx context.Context, nodeID ua.NodeID, value *ua.DataValue) error
}

// HistoryReader provides methods to read historical data.
type HistoryReader interface {

	// ReadEvent reads the events from storage. Implementation returns slice of events for every
	// NodeID provided in 'nodesToRead', given StartTime, EndTime and other parameters in 'details'.
	// Implementation may check context for timeout. Implementation must return desired choice of
	// timestamps. Implementation must return ContinuationPoints if more results are available
	// than can be returned in current call. Implementation must release ContinuationPoints
	// if no further results are desired. See OPC UA Part 11 chapter 6.4.2.2 for Read Event functionality.
	ReadEvent(ctx context.Context, nodesToRead []ua.HistoryReadValueID, details ua.ReadEventDetails,
		timestampsToReturn ua.TimestampsToReturn, releaseContinuationPoints bool) ([]ua.HistoryReadResult, ua.StatusCode)

	// ReadRawModified reads the raw or modified data values from storage. Implementation returns
	// slice of data values for every NodeID provided in 'nodesToRead', given StartTime, EndTime and
	// other parameters in 'details'. Implementation may check context for timeout. Implementation must
	// return desired choice of timestamps. Implementation must return ContinuationPoints if more results
	// are available than can be returned in current call. Implementation must release ContinuationPoints
	// if no further results are desired. See OPC UA Part 11 chapter 6.4.3.2 for Read Raw functionality.
	ReadRawModified(ctx context.Context, nodesToRead []ua.HistoryReadValueID, details ua.ReadRawModifiedDetails,
		timestampsToReturn ua.TimestampsToReturn, releaseContinuationPoints bool) ([]ua.HistoryReadResult, ua.StatusCode)

	// ReadProcessed reads the aggregated values from storage. Implementation returns slice of
	// aggregated data values for every NodeID provided in 'nodesToRead', given StartTime, EndTime and
	// other parameters in 'details'. Implementation may check context for timeout. Implementation must
	// return desired choice of timestamps. Implementation must return ContinuationPoints if more results
	// are available than can be returned in current call. Implementation must release ContinuationPoints
	// if no further results are desired. See OPC UA Part 11 chapter 6.4.4.2 for Read Processed functionality.
	ReadProcessed(ctx context.Context, nodesToRead []ua.HistoryReadValueID, details ua.ReadProcessedDetails,
		timestampsToReturn ua.TimestampsToReturn, releaseContinuationPoints bool) ([]ua.HistoryReadResult, ua.StatusCode)

	// ReadAtTime reads the correlated values from storage. Implementation returns slice of
	// correlated data values for every NodeID provided in 'nodesToRead', given slice of timestamps and
	// other parameters in 'details'. Implementation may check context for timeout. Implementation must
	// return desired choice of timestamps. Implementation must return ContinuationPoints if more results
	// are available than can be returned in current call. Implementation must release ContinuationPoints
	// if no further results are desired. See OPC UA Part 11 chapter 6.4.5.2 for Read At Time functionality.
	ReadAtTime(ctx context.Context, nodesToRead []ua.HistoryReadValueID, details ua.ReadAtTimeDetails,
		timestampsToReturn ua.TimestampsToReturn, releaseContinuationPoints bool) ([]ua.HistoryReadResult, ua.StatusCode)
}
