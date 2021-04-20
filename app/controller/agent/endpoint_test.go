package agent

import "testing"

func TestEndpoint_String(t *testing.T) {
	type fields struct {
		Name       string
		Type       string
		Configured bool
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			"test1",
			fields{Name: "name1", Type: "type1", Configured: true},
			"(type1, name1, true)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Endpoint{
				Name:       tt.fields.Name,
				Type:       tt.fields.Type,
				Configured: tt.fields.Configured,
			}
			if got := e.String(); got != tt.want {
				t.Errorf("Endpoint.String() = %v, want %v", got, tt.want)
			}
		})
	}
}
