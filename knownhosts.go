package main

const (
	// BPF to filter our pcaps by.
	constBPFFilter = "(net 106.185.0.0/16) || (net 27.105.81.0/24) || (net 10.0.0.0/24)"
)

func isLoginServer(port uint16) bool {
	return port == 52100
}

func isWorldServer(port uint16) bool {
	return port == 52000
}

// IsDDONServer checks if the port is a known DDON server port
func IsDDONServer(port uint16) bool {
	return isLoginServer(port) || isWorldServer(port)
}

var (
	knownHosts map[string]string
)

func init() {
	// Initialize our hosts map.
	knownHosts = make(map[string]string)
	knownHosts["106.185.74.101:52100"] = "Login Server"
	knownHosts["106.185.74.173:52000"] = "Game server 1? (seen in stream61)"
	knownHosts["106.185.74.227:52000"] = "Game server 2? (seen in stream61)"
}
