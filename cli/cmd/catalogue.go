package cmd

import (
	"github.com/spf13/cobra"
	"github.com/vandanrohatgi/gocisa"
)

func init() {
	rootCmd.AddCommand(catalogueCmd)
}

var catalogueCmd = &cobra.Command{
	Use:   "get-catalogue",
	Short: "get the KEV catalogue from cisa.gov",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		k := gocisa.GetNewClient()
		k.FetchCatalogue()
	},
}
