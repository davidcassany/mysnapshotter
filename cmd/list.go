/*
Copyright © 2024 SUSE LLC

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
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/containerd/containerd/v2/core/images"
	"github.com/spf13/cobra"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:     "list",
	Short:   "Lists all images",
	Args:    cobra.ExactArgs(0),
	PreRunE: initCS,
	RunE: func(cmd *cobra.Command, args []string) error {
		flags := cmd.Flags()
		imgs, err := cs.List()
		jOut, _ := flags.GetBool("json")
		if err != nil {
			return err
		}

		var tw = tabwriter.NewWriter(os.Stdout, 1, 4, 1, ' ', 0)
		var images []images.Image

		for _, img := range imgs {
			if !jOut {
				fmt.Fprintf(tw, "\t%s\t%s\n", img.Name, img.Target.Digest)
			} else {
				images = append(images, img)
			}
		}

		if !jOut {
			tw.Flush()
		} else {
			jsonBytes, err := json.MarshalIndent(images, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(jsonBytes))
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(listCmd)

	listCmd.Flags().Bool("json", false, "Outpus images metadata in a json")
}
