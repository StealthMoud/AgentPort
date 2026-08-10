package adapter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/StealthMoud/AgentPort/internal/model"
	"github.com/StealthMoud/AgentPort/internal/security"
)

// GenerateStableEntityID generates a deterministic V2 ID from provider and logical source key.
func GenerateStableEntityID(prefix string, provider string, logicalKey string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("agentport_v2_stable:%s:%s:%s", prefix, provider, logicalKey)))
	return fmt.Sprintf("%s_%s", prefix, hex.EncodeToString(h[:])[:16])
}

// ComputeLogicalSourceKey creates a machine-independent relative key for a surface file.
func ComputeLogicalSourceKey(provider string, rootPath string, filePath string) string {
	rel := filePath
	if rootPath != "" && strings.HasPrefix(filePath, rootPath) {
		rel, _ = filepath.Rel(rootPath, filePath)
	}
	rel = filepath.ToSlash(rel)
	return strings.ToLower(provider + "/" + strings.TrimPrefix(rel, "/"))
}

// ParseMCPConfig parses MCP configuration files, strips secret values, and creates MCPToolDef structs.
func ParseMCPConfig(content string) ([]*model.MCPToolDef, error) {
	var rawObj map[string]interface{}
	if err := json.Unmarshal([]byte(content), &rawObj); err != nil {
		return nil, fmt.Errorf("invalid MCP JSON: %w", err)
	}

	var tools []*model.MCPToolDef

	// Check if top-level has "mcpServers" key
	serversObj, hasServers := rawObj["mcpServers"].(map[string]interface{})
	if !hasServers {
		_, hasCmd := rawObj["command"]
		_, hasURL := rawObj["url"]
		if hasCmd || hasURL {
			serversObj = map[string]interface{}{"mcp_tool": rawObj}
		}
	}

	if serversObj == nil {
		return nil, fmt.Errorf("no valid MCP servers found in config")
	}

	for serverName, serverVal := range serversObj {
		sMap, ok := serverVal.(map[string]interface{})
		if !ok {
			continue
		}

		cmd, _ := sMap["command"].(string)
		url, _ := sMap["url"].(string)
		transport, _ := sMap["transport"].(string)

		if transport == "" {
			if url != "" {
				transport = "http"
			} else {
				transport = "stdio"
			}
		}

		var args []string
		if rawArgs, ok := sMap["args"].([]interface{}); ok {
			for _, a := range rawArgs {
				if s, ok := a.(string); ok {
					args = append(args, s)
				}
			}
		}

		var envVarNames []string
		requiresCred := false

		if envMap, ok := sMap["env"].(map[string]interface{}); ok {
			for k, v := range envMap {
				envVarNames = append(envVarNames, k)
				valStr := fmt.Sprintf("%v", v)
				lowerK := strings.ToLower(k)
				if strings.Contains(lowerK, "key") || strings.Contains(lowerK, "token") || strings.Contains(lowerK, "secret") || strings.Contains(lowerK, "auth") || strings.Contains(lowerK, "password") {
					requiresCred = true
				}
				if hasSec, _ := security.ScanContentForSecrets(valStr); hasSec {
					requiresCred = true
				}
			}
			sort.Strings(envVarNames)
		}

		tool := &model.MCPToolDef{
			Name:               serverName,
			Command:            cmd,
			Args:               args,
			URL:                url,
			Transport:          transport,
			EnvVarNames:        envVarNames,
			RequiresCredential: requiresCred,
		}

		tools = append(tools, tool)
	}

	return tools, nil
}

// ParseAgentDef parses agent definition files (.toml, .json, or .md with frontmatter).
func ParseAgentDef(filePath string, content string) (*model.AgentDef, error) {
	base := strings.TrimSuffix(filepath.Base(filePath), filepath.Ext(filepath.Base(filePath)))

	name := base
	description := "Agent definition for " + base
	instructions := content
	modelClass := ""
	var capabilities []string
	var skills []string

	lines := strings.Split(content, "\n")
	var bodyLines []string
	inFrontmatter := false

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if i == 0 && (trimmed == "---" || trimmed == "+++") {
			inFrontmatter = true
			continue
		}
		if inFrontmatter && (trimmed == "---" || trimmed == "+++") {
			inFrontmatter = false
			continue
		}

		if inFrontmatter || strings.HasSuffix(filePath, ".toml") {
			if strings.HasPrefix(trimmed, "name =") || strings.HasPrefix(trimmed, "name:") {
				parts := strings.SplitN(trimmed, "=", 2)
				if len(parts) < 2 {
					parts = strings.SplitN(trimmed, ":", 2)
				}
				if len(parts) == 2 {
					name = strings.Trim(strings.TrimSpace(parts[1]), "\"'")
				}
			} else if strings.HasPrefix(trimmed, "description =") || strings.HasPrefix(trimmed, "description:") {
				parts := strings.SplitN(trimmed, "=", 2)
				if len(parts) < 2 {
					parts = strings.SplitN(trimmed, ":", 2)
				}
				if len(parts) == 2 {
					description = strings.Trim(strings.TrimSpace(parts[1]), "\"'")
				}
			} else if strings.HasPrefix(trimmed, "model =") || strings.HasPrefix(trimmed, "model:") {
				parts := strings.SplitN(trimmed, "=", 2)
				if len(parts) < 2 {
					parts = strings.SplitN(trimmed, ":", 2)
				}
				if len(parts) == 2 {
					modelClass = strings.Trim(strings.TrimSpace(parts[1]), "\"'")
				}
			} else if strings.HasPrefix(trimmed, "developer_prompt =") || strings.HasPrefix(trimmed, "instructions =") {
				parts := strings.SplitN(trimmed, "=", 2)
				if len(parts) == 2 {
					instructions = strings.Trim(strings.TrimSpace(parts[1]), "\"'`")
				}
			}
		} else {
			bodyLines = append(bodyLines, line)
		}
	}

	if len(bodyLines) > 0 && !strings.HasSuffix(filePath, ".toml") {
		instructions = strings.TrimSpace(strings.Join(bodyLines, "\n"))
	}

	return &model.AgentDef{
		Name:                name,
		Description:         description,
		Instructions:        instructions,
		PreferredModelClass: modelClass,
		Capabilities:        capabilities,
		Skills:              skills,
	}, nil
}

// ParseSkillPackage parses a skill package directory or SKILL.md file with strict security checks.
func ParseSkillPackage(filePath string, content string) (*model.SkillPackage, error) {
	if res := security.InspectFileName(filePath); res.Decision == security.DecisionReject {
		return nil, fmt.Errorf("%w: skill file %s (%s)", security.ErrDisallowedFile, filePath, res.Reason)
	}
	if hasSecret, reason := security.ScanContentForSecrets(content); hasSecret {
		return nil, fmt.Errorf("%w: skill content %s (%s)", security.ErrSecretDetected, filePath, reason)
	}

	name := strings.TrimSuffix(filepath.Base(filePath), filepath.Ext(filepath.Base(filePath)))
	if name == "SKILL" || name == "skill" {
		dir := filepath.Dir(filePath)
		name = filepath.Base(dir)
	}

	description := "Skill package " + name
	skillMD := content

	lines := strings.Split(content, "\n")
	if len(lines) > 0 && strings.TrimSpace(lines[0]) == "---" {
		inFM := true
		var bodyLines []string
		for i := 1; i < len(lines); i++ {
			trimmed := strings.TrimSpace(lines[i])
			if trimmed == "---" {
				inFM = false
				continue
			}
			if inFM {
				if strings.HasPrefix(trimmed, "name:") {
					name = strings.Trim(strings.TrimSpace(strings.TrimPrefix(trimmed, "name:")), "\"'")
				} else if strings.HasPrefix(trimmed, "description:") {
					description = strings.Trim(strings.TrimSpace(strings.TrimPrefix(trimmed, "description:")), "\"'")
				}
			} else {
				bodyLines = append(bodyLines, lines[i])
			}
		}
		if len(bodyLines) > 0 {
			skillMD = strings.TrimSpace(strings.Join(bodyLines, "\n"))
		}
	}

	scripts := make(map[string]string)
	references := make(map[string]string)
	assets := make(map[string]string)
	hasExec := false

	skillDir := filepath.Dir(filePath)
	if info, err := os.Stat(skillDir); err == nil && info.IsDir() {
		walkErr := filepath.Walk(skillDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || path == filePath {
				return nil
			}
			rel, _ := filepath.Rel(skillDir, path)
			relSlash := filepath.ToSlash(rel)

			if res := security.InspectFileName(relSlash); res.Decision == security.DecisionReject {
				return fmt.Errorf("%w: skill subfile %s (%s)", security.ErrDisallowedFile, relSlash, res.Reason)
			}

			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}

			subContent := string(data)
			if hasSecret, reason := security.ScanContentForSecrets(subContent); hasSecret {
				return fmt.Errorf("%w: skill subfile content %s (%s)", security.ErrSecretDetected, relSlash, reason)
			}

			if strings.HasPrefix(relSlash, "scripts/") {
				scripts[relSlash] = subContent
				hasExec = true
			} else if strings.HasPrefix(relSlash, "references/") {
				references[relSlash] = subContent
			} else {
				assets[relSlash] = subContent
			}
			return nil
		})
		if walkErr != nil {
			return nil, walkErr
		}
	}

	return &model.SkillPackage{
		Name:           name,
		Description:    description,
		SkillMD:        skillMD,
		Scripts:        scripts,
		References:     references,
		Assets:         assets,
		TrustState:     model.SkillTrustLocalOrigin,
		HasExecutables: hasExec,
	}, nil
}
