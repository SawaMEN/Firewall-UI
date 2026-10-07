package buildinfo

type Info struct {
	Version   string `json:"version"`
	Channel   string `json:"channel"`
	Commit    string `json:"commit"`
	BuildTime string `json:"buildTime"`
}

var (
	Version   = "dev"
	Channel   = "dev"
	Commit    = "unknown"
	BuildTime = ""
)

func Current() Info {
	return Info{
		Version:   Version,
		Channel:   Channel,
		Commit:    Commit,
		BuildTime: BuildTime,
	}
}
