package dnssec

type Settings struct {
	Enabled *bool
}

func (s *Settings) SetDefaults() {
	if s.Enabled == nil {
		enabled := true
		s.Enabled = &enabled
	}
}

func (s Settings) Validate() (err error) { return nil }
