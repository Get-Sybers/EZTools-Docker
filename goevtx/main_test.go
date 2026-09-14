package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Velocidex/ordereddict"
)

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// sysmonEvent builds the go-evtx event shape ({Event:{System,EventData}}) a
// real record parses to, so toRecord/buildPayload are testable without a fixture.
func sysmonEvent() *ordereddict.Dict {
	system := ordereddict.NewDict().
		Set("Provider", ordereddict.NewDict().Set("Name", "Microsoft-Windows-Sysmon")).
		Set("EventID", ordereddict.NewDict().Set("Value", int64(1))).
		Set("Level", int64(4)).
		Set("TimeCreated", ordereddict.NewDict().Set("SystemTime", 1705642462.8337584)).
		Set("EventRecordID", int64(5209)).
		Set("Channel", "Microsoft-Windows-Sysmon/Operational").
		Set("Computer", "DESKTOP-M913391").
		Set("Security", ordereddict.NewDict().Set("UserID", "S-1-5-18"))
	eventData := ordereddict.NewDict().
		Set("ProcessId", int64(6256)).
		Set("Image", `C:\Program Files\Google\Chrome\Application\chrome.exe`).
		Set("User", `DESKTOP-M913391\JDH`)
	return ordereddict.NewDict().Set("Event", ordereddict.NewDict().
		Set("System", system).Set("EventData", eventData))
}

func TestToRecordExtractsSystemFields(t *testing.T) {
	em := sysmonEvent()
	event, _ := ordereddict.GetMap(em, "Event")
	rec, err := toRecord(event, "log.evtx")
	if err != nil {
		t.Fatalf("toRecord: %v", err)
	}
	if rec.EventId != 1 {
		t.Errorf("EventId = %d", rec.EventId)
	}
	if rec.Provider != "Microsoft-Windows-Sysmon" {
		t.Errorf("Provider = %q", rec.Provider)
	}
	if rec.Channel != "Microsoft-Windows-Sysmon/Operational" {
		t.Errorf("Channel = %q", rec.Channel)
	}
	if rec.Computer != "DESKTOP-M913391" {
		t.Errorf("Computer = %q", rec.Computer)
	}
	if rec.EventRecordId != 5209 {
		t.Errorf("EventRecordId = %d", rec.EventRecordId)
	}
	if rec.UserId != "S-1-5-18" {
		t.Errorf("UserId = %q", rec.UserId)
	}
	if rec.MapDescription != nil {
		t.Errorf("MapDescription = %v, want null", rec.MapDescription)
	}
	if rec.TimeCreated == "" || rec.TimeCreated[:4] != "2024" {
		t.Errorf("TimeCreated = %q", rec.TimeCreated)
	}
}

func TestPayloadIsEventDataDataForm(t *testing.T) {
	em := sysmonEvent()
	event, _ := ordereddict.GetMap(em, "Event")
	rec, _ := toRecord(event, "log.evtx")
	// Payload is a JSON string of {"EventData":{"Data":[{"@Name","#text"}...]}}
	var p struct {
		EventData struct {
			Data []map[string]string `json:"Data"`
		} `json:"EventData"`
	}
	if err := json.Unmarshal([]byte(rec.Payload), &p); err != nil {
		t.Fatalf("payload not valid JSON: %v", err)
	}
	got := map[string]string{}
	for _, d := range p.EventData.Data {
		got[d["@Name"]] = d["#text"]
	}
	if got["ProcessId"] != "6256" { // int stringified as EvtxECmd stamps it
		t.Errorf("ProcessId #text = %q", got["ProcessId"])
	}
	if got["Image"] != `C:\Program Files\Google\Chrome\Application\chrome.exe` {
		t.Errorf("Image #text = %q", got["Image"])
	}
	if got["User"] != `DESKTOP-M913391\JDH` {
		t.Errorf("User #text = %q", got["User"])
	}
}

func TestPayloadUserDataPassThrough(t *testing.T) {
	event := ordereddict.NewDict().
		Set("System", ordereddict.NewDict().Set("Channel", "x").Set("Computer", "y")).
		Set("UserData", ordereddict.NewDict().Set("EventXML",
			ordereddict.NewDict().Set("User", `DESKTOP\jdoe`).Set("SessionID", int64(1))))
	rec, err := toRecord(event, "ts.evtx")
	if err != nil {
		t.Fatalf("toRecord: %v", err)
	}
	var p map[string]interface{}
	if err := json.Unmarshal([]byte(rec.Payload), &p); err != nil {
		t.Fatalf("payload JSON: %v", err)
	}
	if _, ok := p["UserData"]; !ok {
		t.Errorf("Payload missing UserData: %s", rec.Payload)
	}
}

func TestAsText(t *testing.T) {
	cases := map[interface{}]string{
		"str": "str", int64(42): "42", float64(12312): "12312",
		true: "true", nil: "",
	}
	for in, want := range cases {
		if got := asText(in); got != want {
			t.Errorf("asText(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestLooksLikeEvtx(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "Security.evtx")
	mustWrite(t, good, append([]byte("ElfFile\x00"), make([]byte, 100)...))
	if !looksLikeEvtx(good) {
		t.Error("ElfFile-signature file not detected as evtx")
	}
	bad := filepath.Join(dir, "notes.txt")
	mustWrite(t, bad, []byte("not an evtx"))
	if looksLikeEvtx(bad) {
		t.Error("non-evtx wrongly detected")
	}
}
