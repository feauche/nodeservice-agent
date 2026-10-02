package main

import (
	"reflect"
	"testing"
)

func TestEnrollmentPanelURLs(t *testing.T) {
	got := enrollmentPanelURLs(
		"https://primary.test/",
		" https://backup.test,https://primary.test/, ,https://second.test/ ",
	)
	want := []string{"https://primary.test", "https://backup.test", "https://second.test"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("urls = %#v, want %#v", got, want)
	}
}
