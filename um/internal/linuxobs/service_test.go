package linuxobs

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// fakeDBusProbe is a synthetic DBusProbe fixture: it records exactly which
// units the adapter asks about and returns canned ActiveState values.
type fakeDBusProbe struct {
	states map[string]string
	err    error
	units  []string
}

func (probe *fakeDBusProbe) ActiveState(_ context.Context, unit string) (string, error) {
	probe.units = append(probe.units, unit)
	if probe.err != nil {
		return "", probe.err
	}
	state, ok := probe.states[unit]
	if !ok {
		return "", errors.New("fixture: unit not present")
	}
	return state, nil
}

func TestDBusServiceProbeMapsOnlyTheAllowlistedUnit(t *testing.T) {
	cases := []struct {
		activeState string
		want        ServiceState
	}{
		{"active", ServiceActive},
		{"inactive", ServiceInactive},
		{"failed", ServiceFailed},
		{"activating", ServiceUnknown},
		{"deactivating", ServiceUnknown},
		{"reloading", ServiceUnknown},
		{"", ServiceUnknown},
	}
	for _, tc := range cases {
		probe := &fakeDBusProbe{states: map[string]string{"sing-box.service": tc.activeState}}
		adapter := DBusServiceProbe{DBus: probe}
		observation, err := adapter.ObserveServices(context.Background())
		if err != nil {
			t.Fatalf("ObserveServices(%q): %v", tc.activeState, err)
		}
		if observation.SingBox != tc.want {
			t.Fatalf("state %q mapped to %q, want %q", tc.activeState, observation.SingBox, tc.want)
		}
		if !reflect.DeepEqual(probe.units, []string{"sing-box.service"}) {
			t.Fatalf("adapter queried %v, want exactly [sing-box.service]", probe.units)
		}
	}
}

func TestDBusServiceProbePropagatesErrors(t *testing.T) {
	fixtureErr := errors.New("fixture: dbus unavailable")
	probe := &fakeDBusProbe{err: fixtureErr}
	if _, err := (DBusServiceProbe{DBus: probe}).ObserveServices(context.Background()); !errors.Is(err, fixtureErr) {
		t.Fatalf("ObserveServices error = %v, want the fixture error", err)
	}
	if !reflect.DeepEqual(probe.units, []string{"sing-box.service"}) {
		t.Fatalf("adapter queried %v", probe.units)
	}
}

func TestDBusServiceProbeWithoutClientIsUnavailable(t *testing.T) {
	if _, err := (DBusServiceProbe{}).ObserveServices(context.Background()); !errors.Is(err, ErrProbeUnavailable) {
		t.Fatalf("nil DBus error = %v, want ErrProbeUnavailable", err)
	}
}

func TestShippedProbesAreUnavailable(t *testing.T) {
	if _, err := (UnavailableDBusProbe{}).ActiveState(context.Background(), "sing-box.service"); !errors.Is(err, ErrProbeUnavailable) {
		t.Fatalf("UnavailableDBusProbe error = %v, want ErrProbeUnavailable", err)
	}
	if _, err := (unavailableServiceProbe{}).ObserveServices(context.Background()); !errors.Is(err, ErrProbeUnavailable) {
		t.Fatalf("unavailableServiceProbe error = %v, want ErrProbeUnavailable", err)
	}
	if _, err := (unavailableSingBoxProbe{}).ObserveSingBox(context.Background()); !errors.Is(err, ErrProbeUnavailable) {
		t.Fatalf("unavailableSingBoxProbe error = %v, want ErrProbeUnavailable", err)
	}
}
