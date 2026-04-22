package output

import "testing"

func TestNewRenderer_OutputFile_NoDirComponent(t *testing.T) {
	// Regression test: filepath.Dir("report.json") returns "."; we should not
	// attempt to create that directory (and should still succeed in creating the file).
	//
	// We don't assert on filesystem effects here (since NewRenderer creates the file);
	// we just ensure it doesn't return an error.
	_, closer, err := NewRenderer(Options{Format: FormatJSON, Output: "portdiff_test_report.json"})
	if err != nil {
		t.Fatalf("NewRenderer returned error: %v", err)
	}
	if closer != nil {
		_ = closer.Close()
	}
}
