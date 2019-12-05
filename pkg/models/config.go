/*
Copyright © 2019 Doppler <support@doppler.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package models

// ConfigFile structure of the config file
type ConfigFile struct {
	ScopedOptions map[string]FileScopedOptions `yaml:"scoped"`
}

// FileScopedOptions config options
type FileScopedOptions struct {
	Token         string `json:"token"`
	Project       string `json:"project"`
	Config        string `json:"config"`
	APIHost       string `json:"api-host"`
	DashboardHost string `json:"dashboard-host"`
	VerifyTLS     string `json:"verify-tls"`
}

// ScopedOptions options with their scope
type ScopedOptions struct {
	Token         ScopedOption `json:"token"`
	Project       ScopedOption `json:"project"`
	Config        ScopedOption `json:"config"`
	APIHost       ScopedOption `json:"api-host"`
	DashboardHost ScopedOption `json:"dashboard-host"`
	VerifyTLS     ScopedOption `json:"verify-tls"`
}

// ScopedOption value and its scope
type ScopedOption struct {
	Value  string `json:"value"`
	Scope  string `json:"scope"`
	Source string `json:"source"`
}

// Source where the value came from
type Source int

// the source of the value
const (
	FlagSource Source = iota
	ConfigFileSource
	EnvironmentSource
	DefaultValueSource
)

func (s Source) String() string {
	return [...]string{"Flag", "Config File", "Environment", "Default Value"}[s]
}

// Pairs get the pairs for the given config
func Pairs(conf FileScopedOptions) map[string]string {
	return map[string]string{
		"token":          conf.Token,
		"project":        conf.Project,
		"config":         conf.Config,
		"api-host":       conf.APIHost,
		"dashboard-host": conf.DashboardHost,
		"verify-tls":     conf.VerifyTLS,
	}
}

// ScopedPairs get the pairs for the given scoped config
func ScopedPairs(conf *ScopedOptions) map[string]*ScopedOption {
	return map[string]*ScopedOption{
		"token":          &conf.Token,
		"project":        &conf.Project,
		"config":         &conf.Config,
		"api-host":       &conf.APIHost,
		"dashboard-host": &conf.DashboardHost,
		"verify-tls":     &conf.VerifyTLS,
	}
}

// EnvPairs get the scoped config pairs for each environment variable
func EnvPairs(conf *ScopedOptions) map[string]*ScopedOption {
	return map[string]*ScopedOption{
		"DOPPLER_TOKEN":          &conf.Token,
		"DOPPLER_PROJECT":        &conf.Project,
		"DOPPLER_CONFIG":         &conf.Config,
		"DOPPLER_API_HOST":       &conf.APIHost,
		"DOPPLER_DASHBOARD_HOST": &conf.DashboardHost,
		"DOPPLER_VERIFY_TLS":     &conf.VerifyTLS,
	}
}
