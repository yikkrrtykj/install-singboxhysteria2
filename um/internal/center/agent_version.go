package center

// OD-LT-14: minimum agent version that understands the optional revision-7
// collect.monitor_export switch.
//
// The frozen rev-5/rev-6 agent config decoder rejects a collect map that is not
// exactly the six frozen keys, so a center must never emit the optional
// monitor_export key to an old or unknown agent. The center therefore gates the
// key on the node's latest authenticated snapshot agent.version (recorded
// atomically during snapshot ingest) being >= this documented minimum.
//
// This is a compatibility gate, not an authorization decision: it is ANDed with
// the operator/admin source switch, the linux_vps class and the deployed rev-7
// agent-config schema. The local agent still re-validates both the six-key and
// seven-key forms.
const MinMonitorExportAgentVersion = "1.1.0"

// agentVersionAtLeast reports whether the reported contract agent.version is at
// least the minimum revision, using semver ordering of the numeric core and
// treating a prerelease of the exact minimum release as older (semver §11). An
// empty/unknown version is never sufficient. Only the frozen agent.version
// grammar (digits dot digits dot digits with an optional -/+ suffix) reaches
// this helper: the contract schema validated it and the store re-checks it.
func agentVersionAtLeast(reported, minimum string) bool {
	reportedCore, reportedPre, ok := parseAgentVersion(reported)
	if !ok {
		return false
	}
	minimumCore, minimumPre, ok := parseAgentVersion(minimum)
	if !ok {
		return false
	}
	for index := range reportedCore {
		if reportedCore[index] != minimumCore[index] {
			return reportedCore[index] > minimumCore[index]
		}
	}
	// Same numeric core: a prerelease is older than the release it precedes.
	if reportedPre != "" && minimumPre == "" {
		return false
	}
	return true
}

// parseAgentVersion parses the frozen `MAJOR.MINOR.PATCH[-pre][+build]` form. The
// build suffix is ignored for ordering.
func parseAgentVersion(version string) (core [3]int64, prerelease string, ok bool) {
	if version == "" || len(version) > 32 {
		return core, "", false
	}
	index := 0
	for field := 0; field < 3; field++ {
		start := index
		var value int64
		for index < len(version) && version[index] >= '0' && version[index] <= '9' {
			value = value*10 + int64(version[index]-'0')
			index++
			if value > 9007199254740991 {
				return core, "", false
			}
		}
		if index == start {
			return core, "", false
		}
		core[field] = value
		if field < 2 {
			if index >= len(version) || version[index] != '.' {
				return core, "", false
			}
			index++
		}
	}
	if index == len(version) {
		return core, "", true
	}
	switch version[index] {
	case '-':
		end := index + 1
		for end < len(version) && version[end] != '+' {
			end++
		}
		if end == index+1 {
			return core, "", false
		}
		prerelease = version[index+1 : end]
		index = end
	case '+':
	default:
		return core, "", false
	}
	if index < len(version) {
		if version[index] != '+' || index+1 >= len(version) {
			return core, "", false
		}
		for suffix := index + 1; suffix < len(version); suffix++ {
			if !isAgentVersionSuffixChar(version[suffix]) {
				return core, "", false
			}
		}
	}
	for suffix := 0; suffix < len(prerelease); suffix++ {
		if !isAgentVersionSuffixChar(prerelease[suffix]) {
			return core, "", false
		}
	}
	return core, prerelease, true
}

func isAgentVersionSuffixChar(char byte) bool {
	return char >= '0' && char <= '9' || char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char == '.' || char == '-'
}
