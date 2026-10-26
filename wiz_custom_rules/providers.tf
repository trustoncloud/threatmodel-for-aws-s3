provider "wiz" {
  # Need to run the following commands with your actual secrets, before running Terraform operations:
  # Otherwise Terraform doesn't work because it's missing credentials

  # export WIZ_URL="https://api.<host>.app.wiz.io/graphql"
  # export WIZ_CLIENT_ID=<your_wiz_client_id>
  # export WIZ_CLIENT_SECRET=<your_wiz_client_secret>

  # To get the WIZ_URL, please click at the user icon on the top right -> Tenant Info
  # Then take note of the API Endpoint URL

  # To get a WIZ_CLIENT_ID and WIZ_CLIENT_SECRET, please follow Settings -> Access Management -> Service Accounts
  # Please make sure to use the type of "Custom Integration (GraphQL API)"
  # Permissions: tick all boxes under the "Cloud Configuration Rule" and the "Cloud Configuration" sections
}
