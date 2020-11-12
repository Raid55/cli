/*
Copyright © 2020 Doppler <support@doppler.com>

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
package cmd

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/DopplerHQ/cli/pkg/configuration"
	"github.com/DopplerHQ/cli/pkg/controllers"
	"github.com/DopplerHQ/cli/pkg/crypto"
	"github.com/DopplerHQ/cli/pkg/http"
	"github.com/DopplerHQ/cli/pkg/models"
	"github.com/DopplerHQ/cli/pkg/printer"
	"github.com/DopplerHQ/cli/pkg/utils"
	"github.com/spf13/cobra"
)

type secretsResponse struct {
	Variables map[string]interface{}
	Success   bool
}

var secretsCmd = &cobra.Command{
	Use:    "secrets",
	Short:  "Manage secrets",
	Args:   cobra.NoArgs,
	PreRun: requiresToken,
	Run:    secrets,
}

var secretsGetCmd = &cobra.Command{
	Use:   "get [secrets]",
	Short: "Get the value of one or more secrets",
	Long: `Get the value of one or more secrets.

Ex: output the secrets "API_KEY" and "CRYPTO_KEY":
doppler secrets get API_KEY CRYPTO_KEY`,
	Args:   cobra.MinimumNArgs(1),
	PreRun: requiresToken,
	Run:    getSecrets,
}

var secretsSetCmd = &cobra.Command{
	Use:   "set [secrets]",
	Short: "Set the value of one or more secrets",
	Long: `Set the value of one or more secrets.

Ex: set the secrets "API_KEY" and "CRYPTO_KEY":
doppler secrets set API_KEY=123 CRYPTO_KEY=456`,
	Args:   cobra.MinimumNArgs(1),
	PreRun: requiresToken,
	Run:    setSecrets,
}

var secretsDeleteCmd = &cobra.Command{
	Use:   "delete [secrets]",
	Short: "Delete the value of one or more secrets",
	Long: `Delete the value of one or more secrets.

Ex: delete the secrets "API_KEY" and "CRYPTO_KEY":
doppler secrets delete API_KEY CRYPTO_KEY`,
	Args:   cobra.MinimumNArgs(1),
	PreRun: requiresToken,
	Run:    deleteSecrets,
}

var secretsDownloadCmd = &cobra.Command{
	Use:   "download <filepath>",
	Short: "Download a config's secrets for later use",
	Long:  `Download your config's secrets for later use. JSON and Env format are supported.`,
	Example: `Save your secrets to /root/ encrypted in JSON format
$ doppler secrets download /root/secrets.json

Save your secrets to /root/ encrypted in Env format
$ doppler secrets download --format=env /root/secrets.env

Print your secrets to stdout in env format without writing to the filesystem
$ doppler secrets download --format=env --no-file`,
	Args:   cobra.MaximumNArgs(1),
	PreRun: requiresToken,
	Run:    downloadSecrets,
}

// TODO: revision the short, long, and example text
var secretsSubstituteCmd = &cobra.Command{
	Use: "substitute <input file/dir> <output dir>",
	// TODO: add path to docs or remove
	Short: "Substitutes secrets in files, must be formated acording to used parse, see <INSERT DOCS OR WHATEVER>",
	Long:  `Parses through the input file/dir looking for matching patterns to replace them with their respective secret`,
	Example: `Fill a .env file to fill it with secrets.
$ cat ./.env.template
DB_URL=${MASTER_DB}
$ doppler secrets substitute ./.env.template .
$ cat ./.env
DB_URL=postgres://john:admin@us-west-2.amazonaws.com:5432/default

Target multiple files in a dir to be substituted and create output dir
$ ls ./secrets_templates
db_secrets.yaml
api_secrets.yaml
$ doppler secrets substitute ./secrets_templates ./secrets
$ ls ./secrets
db_secrets.yaml
api_secrets.yaml

Choose an alternate variable expression for secrets, using default output
$ doppler secrets substitute ./.env.template . --var-exp=handlebars`,
	// TODO: add dev logs for errors
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 2 {
			utils.HandleError(fmt.Errorf("missing input and/or output args"))
		}

		inputFilePath, err := utils.GetFilePath(args[0])
		if err != nil {
			utils.HandleError(err)
		} else if _, err := os.Stat(inputFilePath); os.IsPermission(err) {
			utils.HandleError(fmt.Errorf("permission error on input dir: %s", inputFilePath))
		} else if err != nil {
			utils.HandleError(fmt.Errorf("unable to access: %s", inputFilePath))
		} else {
			args[0] = inputFilePath
		}

		outputFilePath, err := utils.GetFilePath(args[1])
		if err != nil {
			utils.HandleError(err)
		}
		if _, er := os.Stat(outputFilePath); os.IsPermission(er) {
			utils.HandleError(fmt.Errorf("permission error on output dir: %s", outputFilePath))
		} else if er != nil && !os.IsNotExist(er) {
			utils.HandleError(fmt.Errorf("unable to access: %s", outputFilePath))
		} else {
			args[1] = outputFilePath
		}

		return nil
	},
	PreRun: requiresToken,
	Run:    substituteSecrets,
}

func requiresToken(cmd *cobra.Command, args []string) {
	localConfig := configuration.LocalConfig(cmd)
	utils.RequireValue("token", localConfig.Token.Value)
}

func secrets(cmd *cobra.Command, args []string) {
	jsonFlag := utils.OutputJSON
	raw := utils.GetBoolFlag(cmd, "raw")
	onlyNames := utils.GetBoolFlag(cmd, "only-names")
	localConfig := configuration.LocalConfig(cmd)

	response, err := http.GetSecrets(localConfig.APIHost.Value, utils.GetBool(localConfig.VerifyTLS.Value, true), localConfig.Token.Value, localConfig.EnclaveProject.Value, localConfig.EnclaveConfig.Value)
	if !err.IsNil() {
		utils.HandleError(err.Unwrap(), err.Message)
	}
	secrets, parseErr := models.ParseSecrets(response)
	if parseErr != nil {
		utils.HandleError(parseErr, "Unable to parse API response")
	}

	if onlyNames {
		printer.SecretsNames(secrets, jsonFlag)
	} else {
		printer.Secrets(secrets, []string{}, jsonFlag, false, raw, false)
	}
}

func getSecrets(cmd *cobra.Command, args []string) {
	jsonFlag := utils.OutputJSON
	plain := utils.GetBoolFlag(cmd, "plain")
	copy := utils.GetBoolFlag(cmd, "copy")
	raw := utils.GetBoolFlag(cmd, "raw")
	localConfig := configuration.LocalConfig(cmd)

	response, err := http.GetSecrets(localConfig.APIHost.Value, utils.GetBool(localConfig.VerifyTLS.Value, true), localConfig.Token.Value, localConfig.EnclaveProject.Value, localConfig.EnclaveConfig.Value)
	if !err.IsNil() {
		utils.HandleError(err.Unwrap(), err.Message)
	}
	secrets, parseErr := models.ParseSecrets(response)
	if parseErr != nil {
		utils.HandleError(parseErr, "Unable to parse API response")
	}

	printer.Secrets(secrets, args, jsonFlag, plain, raw, copy)
}

func setSecrets(cmd *cobra.Command, args []string) {
	jsonFlag := utils.OutputJSON
	raw := utils.GetBoolFlag(cmd, "raw")
	localConfig := configuration.LocalConfig(cmd)

	secrets := map[string]interface{}{}
	var keys []string
	for _, arg := range args {
		secretArr := strings.Split(arg, "=")
		keys = append(keys, secretArr[0])
		if len(secretArr) < 2 {
			secrets[secretArr[0]] = ""
		} else {
			secrets[secretArr[0]] = secretArr[1]
		}
	}

	response, err := http.SetSecrets(localConfig.APIHost.Value, utils.GetBool(localConfig.VerifyTLS.Value, true), localConfig.Token.Value, localConfig.EnclaveProject.Value, localConfig.EnclaveConfig.Value, secrets)
	if !err.IsNil() {
		utils.HandleError(err.Unwrap(), err.Message)
	}

	if !utils.Silent {
		printer.Secrets(response, keys, jsonFlag, false, raw, false)
	}
}

func deleteSecrets(cmd *cobra.Command, args []string) {
	jsonFlag := utils.OutputJSON
	raw := utils.GetBoolFlag(cmd, "raw")
	yes := utils.GetBoolFlag(cmd, "yes")
	localConfig := configuration.LocalConfig(cmd)

	if yes || utils.ConfirmationPrompt("Delete secret(s)", false) {
		secrets := map[string]interface{}{}
		for _, arg := range args {
			secrets[arg] = nil
		}

		response, err := http.SetSecrets(localConfig.APIHost.Value, utils.GetBool(localConfig.VerifyTLS.Value, true), localConfig.Token.Value, localConfig.EnclaveProject.Value, localConfig.EnclaveConfig.Value, secrets)
		if !err.IsNil() {
			utils.HandleError(err.Unwrap(), err.Message)
		}

		if !utils.Silent {
			printer.Secrets(response, []string{}, jsonFlag, false, raw, false)
		}
	}
}

func downloadSecrets(cmd *cobra.Command, args []string) {
	saveFile := !utils.GetBoolFlag(cmd, "no-file")
	jsonFlag := utils.OutputJSON
	localConfig := configuration.LocalConfig(cmd)

	enableFallback := !utils.GetBoolFlag(cmd, "no-fallback")
	enableCache := enableFallback && !utils.GetBoolFlag(cmd, "no-cache")
	fallbackReadonly := utils.GetBoolFlag(cmd, "fallback-readonly")
	fallbackOnly := utils.GetBoolFlag(cmd, "fallback-only")
	exitOnWriteFailure := !utils.GetBoolFlag(cmd, "no-exit-on-write-failure")

	format := cmd.Flag("format").Value.String()
	if jsonFlag {
		format = "json"
	}

	validFormats := []string{"json", "env"}
	if format != "" {
		isValid := false

		for _, val := range validFormats {
			if val == format {
				isValid = true
				break
			}
		}

		if !isValid {
			utils.HandleError(fmt.Errorf("invalid format. Valid formats are %s", strings.Join(validFormats, ", ")))
		}
	}

	fallbackPassphrase := getPassphrase(cmd, "fallback-passphrase", localConfig)
	if fallbackPassphrase == "" {
		utils.HandleError(errors.New("invalid fallback file passphrase"))
	}

	var body []byte
	if format == "json" {
		fallbackPath := ""
		legacyFallbackPath := ""
		metadataPath := ""
		if enableFallback {
			fallbackPath, legacyFallbackPath = initFallbackDir(cmd, localConfig, exitOnWriteFailure)
		}
		if enableCache {
			metadataPath = controllers.MetadataFilePath(localConfig.Token.Value, localConfig.EnclaveProject.Value, localConfig.EnclaveConfig.Value)
		}
		secrets := fetchSecrets(localConfig, enableCache, enableFallback, fallbackPath, legacyFallbackPath, metadataPath, fallbackReadonly, fallbackOnly, exitOnWriteFailure, fallbackPassphrase)

		var err error
		body, err = json.Marshal(secrets)
		if err != nil {
			utils.HandleError(err, "Unable to parse JSON secrets")
		}
	} else {
		// fallback file is not supported when fetching .env format
		enableFallback = false
		enableCache = false
		flags := []string{"fallback", "fallback-only", "fallback-readonly", "no-exit-on-write-failure"}
		for _, flag := range flags {
			if cmd.Flags().Changed(flag) {
				utils.LogWarning(fmt.Sprintf("--%s has no effect when format is %s", flag, format))
			}
		}

		var apiError http.Error
		_, _, body, apiError = http.DownloadSecrets(localConfig.APIHost.Value, utils.GetBool(localConfig.VerifyTLS.Value, true), localConfig.Token.Value, localConfig.EnclaveProject.Value, localConfig.EnclaveConfig.Value, false, "")
		if !apiError.IsNil() {
			utils.HandleError(apiError.Unwrap(), apiError.Message)
		}
	}

	if !saveFile {
		fmt.Println(string(body))
		return
	}

	var filePath string
	if len(args) > 0 {
		var err error
		filePath, err = utils.GetFilePath(args[0])
		if err != nil {
			utils.HandleError(err, "Unable to parse download file path")
		}
	} else if format == "env" {
		filePath = filepath.Join(".", "doppler.env")
	} else {
		filePath = filepath.Join(".", "doppler.json")
	}

	utils.LogDebug("Encrypting secrets")

	passphrase := getPassphrase(cmd, "passphrase", localConfig)
	if passphrase == "" {
		utils.HandleError(errors.New("invalid passphrase"))
	}

	encryptedBody, err := crypto.Encrypt(passphrase, body)
	if err != nil {
		utils.HandleError(err, "Unable to encrypt your secrets. No file has been written.")
	}

	if err := utils.WriteFile(filePath, []byte(encryptedBody), utils.RestrictedFilePerms()); err != nil {
		utils.HandleError(err, "Unable to write the secrets file")
	}

	utils.Log(fmt.Sprintf("Downloaded secrets to %s", filePath))
}

// TODO: unittests
func substituteSecrets(cmd *cobra.Command, args []string) {
	localConfig := configuration.LocalConfig(cmd)
	varExp := cmd.Flag("var-exp").Value.String()
	bufferSize := utils.GetIntFlag(cmd, "buffer-size", 16)
	inputFilePath := args[0]
	outputFilePath := args[1]

	response, err := http.GetSecrets(localConfig.APIHost.Value, utils.GetBool(localConfig.VerifyTLS.Value, true), localConfig.Token.Value, localConfig.EnclaveProject.Value, localConfig.EnclaveConfig.Value)
	if !err.IsNil() {
		utils.HandleError(err.Unwrap(), err.Message)
	}
	secrets, parseErr := models.ParseSecrets(response)
	if parseErr != nil {
		utils.HandleError(parseErr, "Unable to parse API response")
	}

	substituteText := models.VarExpressions[varExp]
	if substituteText == nil {
		utils.HandleError(fmt.Errorf("invalid var-exp: %s", varExp))
	}

	if _, err := os.Stat(outputFilePath); os.IsNotExist(err) {
		fmt.Println("I want you to notice")
		// TODO: remove hardcode perms, better safe perms
		err := utils.MakeDir(outputFilePath, 0755)
		if err != nil {
			utils.HandleError(fmt.Errorf("can't create output dir: %s", outputFilePath))
		}
	}

	var subFileList []string
	if file, _ := os.Stat(inputFilePath); file.IsDir() {
		files, err := utils.ListDir(inputFilePath)
		if err != nil {
			utils.HandleError(fmt.Errorf("can't read input path: %s", inputFilePath))
		}

		for _, f := range files {
			filePath := filepath.Join(inputFilePath, f.Name())
			if f, err := os.Stat(filePath); err != nil {
				utils.HandleError(fmt.Errorf("permission error for file: %s", filePath))
			} else if !f.IsDir() {
				subFileList = append(subFileList, filePath)
			}
		}
	} else {
		subFileList = append(subFileList, inputFilePath)
	}

	var waitGroup sync.WaitGroup
	for _, subFilepath := range subFileList {
		waitGroup.Add(1)

		// TODO: refactor, codesplit io funcs
		// TODO: better errors, more though out flow
		go func(wg *sync.WaitGroup, subFp string) {
			defer wg.Done()

			inFile, err := os.Open(subFp)
			if err != nil {
				utils.HandleError(err)
			}
			defer inFile.Close()

			outFilename := filepath.Join(outputFilePath, filepath.Base(inFile.Name()))
			tempOutFilename := fmt.Sprintf("%s.%s", outFilename, utils.RandomBase64String(8))
			defer os.Rename(tempOutFilename, outFilename)

			outFile, err := os.OpenFile(tempOutFilename, os.O_CREATE|os.O_WRONLY, utils.RestrictedFilePerms())
			if err != nil {
				utils.HandleError(err)
			}
			defer outFile.Close()

			reader := bufio.NewReader(inFile)
			writer := bufio.NewWriterSize(
				outFile,
				bufferSize,
			)
			defer writer.Flush()

			for {
				token, err := utils.ReadSliceFromReader(reader)

				if err := utils.WriteToBuffer(writer, substituteText(token, secrets)); err != nil {
					utils.HandleError(err)
				}

				if err != nil {
					break
				}
			}
		}(&waitGroup, subFilepath)
	}

	fmt.Println("Substituting Files...")
	waitGroup.Wait()
	fmt.Printf("Substituted %s to %s", inputFilePath, outputFilePath)
}

func init() {
	secretsCmd.Flags().StringP("project", "p", "", "project (e.g. backend)")
	secretsCmd.Flags().StringP("config", "c", "", "config (e.g. dev)")
	secretsCmd.Flags().Bool("raw", false, "print the raw secret value without processing variables")
	secretsCmd.Flags().Bool("only-names", false, "only print the secret names; omit all values")

	secretsGetCmd.Flags().StringP("project", "p", "", "project (e.g. backend)")
	secretsGetCmd.Flags().StringP("config", "c", "", "config (e.g. dev)")
	secretsGetCmd.Flags().Bool("plain", false, "print values without formatting")
	secretsGetCmd.Flags().Bool("copy", false, "copy the value(s) to your clipboard")
	secretsGetCmd.Flags().Bool("raw", false, "print the raw secret value without processing variables")
	secretsCmd.AddCommand(secretsGetCmd)

	secretsSetCmd.Flags().StringP("project", "p", "", "project (e.g. backend)")
	secretsSetCmd.Flags().StringP("config", "c", "", "config (e.g. dev)")
	secretsSetCmd.Flags().Bool("raw", false, "print the raw secret value without processing variables")
	secretsCmd.AddCommand(secretsSetCmd)

	secretsDeleteCmd.Flags().StringP("project", "p", "", "project (e.g. backend)")
	secretsDeleteCmd.Flags().StringP("config", "c", "", "config (e.g. dev)")
	secretsDeleteCmd.Flags().Bool("raw", false, "print the raw secret value without processing variables")
	secretsDeleteCmd.Flags().BoolP("yes", "y", false, "proceed without confirmation")
	secretsCmd.AddCommand(secretsDeleteCmd)

	secretsDownloadCmd.Flags().StringP("project", "p", "", "project (e.g. backend)")
	secretsDownloadCmd.Flags().StringP("config", "c", "", "config (e.g. dev)")
	secretsDownloadCmd.Flags().String("format", "json", "output format. one of [json, env]")
	secretsDownloadCmd.Flags().String("passphrase", "", "passphrase to use for encrypting the secrets file. the default passphrase is computed using your current configuration.")
	secretsDownloadCmd.Flags().Bool("no-file", false, "print the response to stdout")
	// fallback flags
	secretsDownloadCmd.Flags().String("fallback", "", "path to the fallback file. encrypted secrets are written to this file after each successful fetch. secrets will be read from this file if subsequent connections are unsuccessful.")
	secretsDownloadCmd.Flags().Bool("no-cache", false, "disable using the fallback file to speed up fetches. the fallback file is only used when the API indicates that it's still current.")
	secretsDownloadCmd.Flags().Bool("no-fallback", false, "disable reading and writing the fallback file")
	secretsDownloadCmd.Flags().String("fallback-passphrase", "", "passphrase to use for encrypting the fallback file. by default the passphrase is computed using your current configuration.")
	secretsDownloadCmd.Flags().Bool("fallback-readonly", false, "disable modifying the fallback file. secrets can still be read from the file.")
	secretsDownloadCmd.Flags().Bool("fallback-only", false, "read all secrets directly from the fallback file, without contacting Doppler. secrets will not be updated. (implies --fallback-readonly)")
	secretsDownloadCmd.Flags().Bool("no-exit-on-write-failure", false, "do not exit if unable to write the fallback file")
	secretsCmd.AddCommand(secretsDownloadCmd)

	// TODO: is var-exp ok as a flag name?
	secretsSubstituteCmd.Flags().Int("buffer-size", 4096, "size of buffer used to copy substitute files")
	secretsSubstituteCmd.Flags().String("var-exp", "dollar-curly", "variable expression formate used to substitute secrets [dollar,dollar-curly,handlebars,dollar-handlebars]")
	secretsCmd.AddCommand(secretsSubstituteCmd)

	rootCmd.AddCommand(secretsCmd)
}
