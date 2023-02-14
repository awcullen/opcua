package ua_test

import (
	"testing"
	"time"

	"github.com/awcullen/opcua/ua"
	"github.com/pkg/errors"
)

func TestDeserializeBaseEvent(t *testing.T) {
	f := []ua.Variant{
		ua.ByteString("foo"),
		ua.NewNodeIDString(1, "bar"),
		ua.NewNodeIDString(1, "bar"),
		"source",
		time.Now().UTC(),
		time.Now().UTC(),
		ua.NewLocalizedText("Temperature is high.", "en"),
		uint16(255),
	}
	e := ua.BaseEvent{}
	if err := e.UnmarshalFields(f); err != nil {
		t.Error(errors.Wrap(err, "Error unmarshalling fields"))
	}
	t.Logf("%+v", e)
}

func TestDeserializeCondition(t *testing.T) {
	f := []ua.Variant{
		ua.ByteString("foo"),
		ua.NewNodeIDString(1, "bar"),
		ua.NewNodeIDString(1, "bar"),
		"source",
		time.Now().UTC(),
		time.Now().UTC(),
		ua.NewLocalizedText("Temperature is high.", "en"),
		uint16(255),
		ua.NewNodeIDNumeric(1, 45),
		"ConditionName",
		nil,
		true,
	}
	e := ua.Condition{}
	if err := e.UnmarshalFields(f); err != nil {
		t.Error(errors.Wrap(err, "Error unmarshalling fields"))
	}
	t.Logf("%+v", e)
}
