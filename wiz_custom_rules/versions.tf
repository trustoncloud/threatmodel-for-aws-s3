terraform {
  required_version = ">= 1.0"
  required_providers {
    wiz = {
      source  = "tf.app.wiz.io/wizsec/wiz"
      version = ">= 1.12.3311"
    }
  }
}
