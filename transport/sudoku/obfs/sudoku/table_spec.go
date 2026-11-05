package sudoku

func ValidateTableSpecs(mode string, customPatterns []string) error {
	asciiMode, err := ParseASCIIMode(mode)
	if err != nil {
		return err
	}
	for _, customPattern := range customPatterns {
		if _, err = resolveLayout(asciiMode.uplinkPreference(), customPatternForToken(asciiMode.Uplink, customPattern)); err != nil {
			return err
		}
		if asciiMode.Uplink == asciiMode.Downlink {
			continue
		}
		if _, err = resolveLayout(asciiMode.downlinkPreference(), customPatternForToken(asciiMode.Downlink, customPattern)); err != nil {
			return err
		}
	}
	return nil
}
