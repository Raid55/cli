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
package utils

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

// RestrictedFilePerms perms used for creating restrictied files meant to be accessible only to the user
func RestrictedFilePerms() os.FileMode {
	// windows disallows overwriting an existing file with 0400 perms
	if IsWindows() {
		return 0600
	}

	return 0400
}

// MakeDir makes dir at path with perms
func MakeDir(path string, perms os.FileMode) error {
	return os.Mkdir(path, perms)
}

// WriteFile atomically writes data to a file named by filename.
func WriteFile(filename string, data []byte, perm os.FileMode) error {
	temp := fmt.Sprintf("%s.%s", filename, RandomBase64String(8))

	// write to a unique temp file first before performing an atomic move to the actual file name
	// this prevents a race condition between multiple CLIs reading/writing the same file
	LogDebug(fmt.Sprintf("Writing to temp file %s", temp))
	if err := ioutil.WriteFile(temp, data, os.FileMode(perm)); err != nil {
		return err
	}

	LogDebug(fmt.Sprintf("Renaming temp file to %s", filename))
	if err := os.Rename(temp, filename); err != nil {
		// clean up temp file
		_ = os.Remove(temp)
		return err
	}

	return nil
}

// WriteTempFile writes data to a unique temp file and returns the file name
func WriteTempFile(name string, data []byte, perm os.FileMode) (string, error) {
	// create hidden file in user's home dir to ensure no other users have write access
	tmpFile, err := ioutil.TempFile(HomeDir(), fmt.Sprintf(".%s.", name))
	if err != nil {
		return "", err
	}

	LogDebug(fmt.Sprintf("Writing to temp file %s", tmpFile.Name()))
	if _, err := tmpFile.Write(data); err != nil {
		return "", err
	}

	tmpFileName := tmpFile.Name()
	if err := tmpFile.Close(); err != nil {
		return "", err
	}

	if err := os.Chmod(tmpFileName, perm); err != nil {
		return "", err
	}

	return tmpFileName, nil
}

// ListFiles list accessible files in dir, err if one file is not accessible.
func ListFiles(path string) ([]string, error) {
	var fileList []string
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return fileList, err
	}

	for _, f := range files {
		filePath := filepath.Join(path, f.Name())
		if f, err := os.Stat(filePath); err != nil {
			return fileList, fmt.Errorf("permission error for file: %s", filePath)
		} else if !f.IsDir() {
			fileList = append(fileList, filePath)
		}
	}

	return fileList, nil
}

// TextProcessor takes bytes, processes them, returns bytes
type TextProcessor func([]byte) []byte

// ProcessFile will read a file efficiently, run a TextProcessor func over each, and write the output to a tmp file.
// tmp file will be renamed to original file once done if outputPath is identical to loc. of inputFile.
func ProcessFile(inputFile string, outputPath string, txtProcessorFn TextProcessor, buffSize int) error {
	inFile, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer inFile.Close()

	outFilepath := filepath.Join(outputPath, filepath.Base(inFile.Name()))
	tmpOutFilepath := fmt.Sprintf("%s.%s", outFilepath, RandomBase64String(8))
	outFile, err := os.OpenFile(tmpOutFilepath, os.O_CREATE|os.O_WRONLY, RestrictedFilePerms())
	if err != nil {
		return err
	}
	defer os.Rename(tmpOutFilepath, outFilepath)
	defer outFile.Close()

	reader := bufio.NewReader(inFile)
	writer := bufio.NewWriterSize(
		outFile,
		buffSize,
	)

	for {
		slice, err := reader.ReadSlice('\n')

		data := txtProcessorFn(slice)
		if _, err := writer.Write(data); err != nil {
			return err
		}

		if err != nil {
			break
		}
	}
	defer writer.Flush()

	return nil
}
