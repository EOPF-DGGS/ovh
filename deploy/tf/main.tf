terraform {
  required_version = "~> 1.6"
  required_providers {
    ovh = {
      source  = "ovh/ovh"
      version = "~> 0.36.1"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    harbor = {
      source  = "BESTSELLER/harbor"
      version = "~> 3.7"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.25"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.12"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    openstack = {
       source  = "terraform-provider-openstack/openstack"
       version = "~> 3.0.0"
    }
  }
  # store state on gcs, like other clusters
  backend "s3" {
    bucket                      = "grid4earth"
    key                         = "grid4earth-state.tfstate"
    region                      = "gra"
    endpoint                    = "https://s3.gra.io.cloud.ovh.net"
    skip_credentials_validation = true
    skip_requesting_account_id  = true
    skip_region_validation      = true
  }
}

provider "ovh" {
  endpoint = "ovh-eu"
  # credentials loaded via source ./secrets/ovh-creds.sh
}

provider "openstack" {
  auth_url = "https://auth.cloud.ovh.net/v3"
  tenant_id = local.service_name
  tenant_name = local.os_tenant_name
}

locals {
  #service_name   = "2a0ebfcd5a8d46a797b921841717b052"
  #os_tenant_name = "4396734720592405"
  # recupere par Fred sur OVHCloud / Horizon Identity
  service_name   = "24b43ff90f3044c8923063b0fbb53f26"
  os_tenant_name = "2512041153854117"
  cluster_name   = "g4e"
  region         = "GRA9"
  #region         = "GRA11"   # ca n'existe pas
  s3_region      = "gra"
  #s3_endpoint    = "https://s3.gra.perf.cloud.ovh.net"
  s3_endpoint    = "https://s3.gra.io.cloud.ovh.net"
  s3_buckets = toset([
  #  "g4e-vliz",
  #  "g4e-ifremer",
    "g4e-reference-data",
  #  "destine-g4e-data-lake",
    "grid4earth",   # ajout FP 2026m01d09
  ])

  # users must appear in only one of these sets
  # because each user can have exactly one policy
  s3_readonly_users = toset([
    "_default",
    "sebastien-tetaud", # Sebastien Tétaud
  ])
  s3_admins = toset([
    "fpaulifr", # Frederic Paul
    "j34ni", # Jean Iaquinta
    #"todaka",
    #"minrk",
  ])

  s3_ifremer_developers = toset([
    "keewis", # Justus Magin
  ])
  s3_ifremer_users = toset([
    "jmdelouis", # Jean-Marc Delouis
    "tinaok" # Tina Odaka
  ])
  # s3_vliz_users = toset([
  # ])
  #s3_users = setunion(local.s3_readonly_users, local.s3_admins, local.s3_vliz_users, local.s3_ifremer_developers, local.s3_ifremer_users)
  s3_users = setunion(local.s3_readonly_users, local.s3_admins, local.s3_ifremer_developers, local.s3_ifremer_users)
  # the s3 policy Action for read-only access
  s3_readonly_action = [
    "s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation",
  ]
  # the s3 policy Action for FULL_CONTROL read/write access
  s3_admin_action = [
    "s3:GetObject", "s3:PutObject", "s3:ListBucket",
    "s3:DeleteObject", "s3:GetObjectAcl", "s3:PutObjectAcl",
    "s3:GetObjectTagging",
    "s3:ListMultipartUploadParts", "s3:ListBucketMultipartUploads",
    "s3:AbortMultipartUpload", "s3:GetBucketLocation",
  ]

  # everyone can read these buckets
  s3_read_public = {
    "Sid" : "Admin",
    "Effect" : "Allow",
    "Action" : local.s3_readonly_action,
    "Resource" : [
      # "arn:aws:s3:::${aws_s3_bucket.g4e-data-lake.id}",
      # "arn:aws:s3:::${aws_s3_bucket.g4e-data-lake.id}/*",
      "arn:aws:s3:::${aws_s3_bucket.g4e-reference-data.id}",
      "arn:aws:s3:::${aws_s3_bucket.g4e-reference-data.id}/*",
    ]
  }
  # default-deny policy
  # disallows bucket creation
  s3_default_deny = {
    "Sid" : "default-deny",
    "Effect" : "Deny",
    "Action" : [
      "s3:CreateBucket",
      "s3:DeleteBucket",
    ],
    "Resource" : ["arn:aws:s3:::*"]
  }

  # default policy:
  # read access to data lake, reference data
  # and deny creation
  s3_default_policy = [
    local.s3_read_public,
    local.s3_default_deny,
  ]
}

####### s3 buckets #######

resource "ovh_cloud_project_user" "s3_admin" {
  service_name = local.service_name
  description  = "admin s3 from OpenTofu"
  role_name    = "objectstore_operator"
}

resource "ovh_cloud_project_user_s3_credential" "s3_admin" {
  service_name = local.service_name
  user_id      = ovh_cloud_project_user.s3_admin.id
}


# Configure the AWS Provider
provider "aws" {
  region     = local.s3_region
  access_key = ovh_cloud_project_user_s3_credential.s3_admin.access_key_id
  secret_key = ovh_cloud_project_user_s3_credential.s3_admin.secret_access_key

  #OVH implementation has no STS service
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  # the gra region is unknown to AWS hence skipping is needed.
  skip_region_validation = true
  endpoints {
    s3 = local.s3_endpoint
  }
}

resource "ovh_cloud_project_user" "s3_users" {
  for_each     = local.s3_users
  service_name = local.service_name
  description  = each.key
  role_name    = "objectstore_operator"
}

resource "ovh_cloud_project_user_s3_credential" "s3_users" {
  for_each     = local.s3_users
  service_name = local.service_name
  user_id      = ovh_cloud_project_user.s3_users[each.key].id
}

# don't need this right now
# this is another way to grant s3 super-user
# instead, use ACLs below
resource "ovh_cloud_project_user_s3_policy" "s3_admins" {
  for_each     = local.s3_admins
  service_name = local.service_name
  user_id      = ovh_cloud_project_user.s3_users[each.key].id
  policy = jsonencode({
    "Statement" : [
      {
        "Sid" : "admin",
        "Effect" : "Allow",
        "Action" : local.s3_admin_action,
        "Resource" : [
          "arn:aws:s3:::*",
        ]
      },
    ]
  })
}

resource "ovh_cloud_project_user_s3_policy" "s3_users" {
  for_each     = local.s3_readonly_users
  service_name = local.service_name
  user_id      = ovh_cloud_project_user.s3_users[each.key].id
  policy = jsonencode({
    "Statement" : local.s3_default_policy,
  })
}

resource "ovh_cloud_project_user_s3_policy" "s3_ifremer_users" {
  for_each     = local.s3_ifremer_users
  service_name = local.service_name
  user_id      = ovh_cloud_project_user.s3_users[each.key].id
  policy = jsonencode({
    "Statement" : concat([
      {
        "Sid" : "Admin",
        "Effect" : "Allow",
        "Action" : local.s3_admin_action,
        "Resource" : [
          #"arn:aws:s3:::${aws_s3_bucket.g4e-ifremer.id}",
          #"arn:aws:s3:::${aws_s3_bucket.g4e-ifremer.id}/*",
          "arn:aws:s3:::grid4earth", 
          "arn:aws:s3:::grid4earth/*"
        ]
      },
    ], local.s3_default_policy)
  })
}

resource "ovh_cloud_project_user_s3_policy" "s3_ifremer_developers" {
  for_each     = setunion(local.s3_ifremer_developers)
  service_name = local.service_name
  user_id      = ovh_cloud_project_user.s3_users[each.key].id
  policy = jsonencode({
    "Statement" : concat([
      {
        "Sid" : "Admin",
        "Effect" : "Allow",
        "Action" : local.s3_admin_action,
        "Resource" : [
          #"arn:aws:s3:::${aws_s3_bucket.g4e-ifremer.id}",
          #"arn:aws:s3:::${aws_s3_bucket.g4e-ifremer.id}/*",
          "arn:aws:s3:::${aws_s3_bucket.g4e-reference-data.id}",
          "arn:aws:s3:::${aws_s3_bucket.g4e-reference-data.id}/*",
        ]
      },
    ], local.s3_default_policy)
  })
}

# resource "ovh_cloud_project_user_s3_policy" "s3_vliz_users" {
#   for_each     = local.s3_vliz_users
#   service_name = local.service_name
#   user_id      = ovh_cloud_project_user.s3_users[each.key].id
#   policy = jsonencode({
#     "Statement" : concat([
#       {
#         "Sid" : "Admin",
#         "Effect" : "Allow",
#         "Action" : local.s3_admin_action,
#         "Resource" : [
#           "arn:aws:s3:::${aws_s3_bucket.g4e-vliz.id}",
#           "arn:aws:s3:::${aws_s3_bucket.g4e-vliz.id}/*",
#         ]
#       },
#     ], local.s3_default_policy)
#   })
# }
data "aws_canonical_user_id" "current" {}


# resource "aws_s3_bucket" "g4e-data-lake" {
#   bucket = "destine-g4e-data-lake"
# }

resource "aws_s3_bucket" "g4e-reference-data" {
  bucket = "g4e-reference-data"
}

#resource "aws_s3_bucket" "g4e-ifremer" {
#  bucket = "g4e-ifremer"
#}

# resource "aws_s3_bucket" "g4e-vliz" {
#   bucket = "g4e-vliz"
# }

resource "aws_s3_bucket" "grid4earth" {
  bucket = "grid4earth"
}

# resource "aws_s3_bucket_acl" "g4e-data-lake" {
#   bucket = aws_s3_bucket.g4e-data-lake.id
#   access_control_policy {
#     # everyone authenticated can read
#     grant {
#       grantee {
#         type = "Group"
#         uri  = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
#       }
#       permission = "READ"
#     }

#     owner {
#       id = data.aws_canonical_user_id.current.id
#     }
#   }
# }

resource "aws_s3_bucket_acl" "g4e-reference-data" {
  bucket = aws_s3_bucket.g4e-reference-data.id
  access_control_policy {
    # everyone authenticated can read reference data
    grant {
      grantee {
        type = "Group"
        uri  = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
      }
      permission = "READ"
    }

    owner {
      id = data.aws_canonical_user_id.current.id
    }
  }
}


resource "aws_s3_bucket_acl" "grid4earth_acl" {
  bucket = aws_s3_bucket.grid4earth.id
  #acl    = "authenticated-read"
  acl    = "public-read"
}

## Organisation du bucket "grid4earth"

# Dossier public (public-read) dans le bucket grid4earth
resource "aws_s3_object" "grid4earth_public_marker" { 
  bucket = aws_s3_bucket.grid4earth.id
  key    = "public/test.txt"
  content = "This is a marker file to initialize public access"
}
resource "null_resource" "public_acl" {
  triggers = {
    bucket = aws_s3_bucket.grid4earth.id
    key    = aws_s3_object.grid4earth_public_marker.key
  }
  provisioner "local-exec" {
    command = <<EOT
      aws s3api put-object-acl --bucket ${aws_s3_bucket.grid4earth.bucket} --key ${aws_s3_object.grid4earth_public_marker.key} --acl public-read --endpoint-url ${local.s3_endpoint}
    EOT
  }
}



output "s3_credentials" {
  description = "s3 credentials for g4e import"
  sensitive   = true
  value = {
    for name in local.s3_users :
    name => <<-EOF
    [g4e]
    aws_access_key_id=${ovh_cloud_project_user_s3_credential.s3_users[name].access_key_id}
    aws_secret_access_key=${ovh_cloud_project_user_s3_credential.s3_users[name].secret_access_key}
    aws_endpoint_url=https://s3.gra.io.cloud.ovh.net
    EOF
  }
}

output "s3_credentials_json" {
  description = "s3 credentials for g4e import"
  sensitive   = true
  value = {
    for name in local.s3_users :
    name => {
      aws_access_key_id     = ovh_cloud_project_user_s3_credential.s3_users[name].access_key_id
      aws_secret_access_key = ovh_cloud_project_user_s3_credential.s3_users[name].secret_access_key
    }
  }
}

output "s3_admin_credentials" {
  description = "s3 credentials for administration"
  sensitive   = true
  value = {
    access_key_id     = ovh_cloud_project_user_s3_credential.s3_admin.access_key_id,
    secret_access_key = ovh_cloud_project_user_s3_credential.s3_admin.secret_access_key,
  }
}

######### Kubernetes ##########


# create a private network for our cluster
resource "ovh_cloud_project_network_private" "network" {
  service_name = local.service_name
  name         = "g4e" # local.cluster_name
  regions      = [local.region]
}

resource "ovh_cloud_project_network_private_subnet" "subnet" {
  service_name = local.service_name
  network_id   = ovh_cloud_project_network_private.network.id

  region  = local.region
  start   = "10.0.0.100"
  end     = "10.0.0.254"
  network = "10.0.0.0/24"
  dhcp    = true
}

resource "ovh_cloud_project_kube" "cluster" {
  service_name = local.service_name
  name         = local.cluster_name
  region       = local.region
  # version      = "1.28"
  # make sure we wait for the subnet to exist
  depends_on = [ovh_cloud_project_network_private_subnet.subnet]

  # private_network_id is an openstackid for some reason?
  private_network_id = tolist(ovh_cloud_project_network_private.network.regions_attributes)[0].openstackid

  # customization_apiserver {
  #   admissionplugins {
  #     enabled = ["NodeRestriction"]
  #     # disable AlwaysPullImages, which causes problems
  #     disabled = ["AlwaysPullImages"]
  #   }
  # }
  update_policy = "MINIMAL_DOWNTIME"
}


# ovh node flavors: https://www.ovhcloud.com/en/public-cloud/prices/

resource "ovh_cloud_project_kube_nodepool" "core" {
  service_name = local.service_name
  kube_id      = ovh_cloud_project_kube.cluster.id
  name         = "core-202401"
  # b2-15 is 4 core, 15GB
  flavor_name = "b3-8"
  max_nodes   = 2
  min_nodes   = 1
  autoscale   = true
  template {
    metadata {
      annotations = {}
      finalizers  = []
      labels = {
        "hub.jupyter.org/node-purpose" = "core"
      }
    }
    spec {
      unschedulable = false
      taints        = []
    }
  }
  lifecycle {
    ignore_changes = [
      # don't interfere with autoscaling
      desired_nodes
    ]
  }
}

resource "ovh_cloud_project_kube_nodepool" "users" {
  service_name = local.service_name
  kube_id      = ovh_cloud_project_kube.cluster.id
  name         = "user-202403"
  # b3-32 is 8-core, 32GB
  flavor_name = "b3-32"
  max_nodes   = 2
  min_nodes   = 1
  autoscale   = true
  template {
    metadata {
      annotations = {}
      finalizers  = []
      labels = {
        "hub.jupyter.org/node-purpose" = "user"
      }
    }
    spec {
      unschedulable = false
      taints        = []
    }
  }
  lifecycle {
    ignore_changes = [
      # don't interfere with autoscaling
      desired_nodes,
      # seems to be something weird going on here
      # with metadata labels
      template,
    ]
  }
}

resource "ovh_cloud_project_kube_nodepool" "user-big" {
  service_name = local.service_name
  kube_id      = ovh_cloud_project_kube.cluster.id
  name         = "user-big-202405"
  # r3-512 is 64 core, 512 GB
  # current quota is 512 CPU, 4 TB RAM
  # which is slightly less than 8 of these
  # assuming nothing else is running
  flavor_name = "r3-512"
  max_nodes   = 6
  min_nodes   = 0
  autoscale   = true
  template {
    metadata {
      annotations = {}
      finalizers  = []
      labels = {
        "hub.jupyter.org/node-purpose"   = "user"
        "g4e.destination-earth.eu/size" = "big512"
      }
    }
    spec {
      unschedulable = false
      taints        = []
    }
  }
  lifecycle {
    ignore_changes = [
      # don't interfere with autoscaling
      desired_nodes,
      # seems to be something weird going on here
      # with metadata labels
      template,
    ]
  }
}


output "kubeconfig" {
  value       = ovh_cloud_project_kube.cluster.kubeconfig
  sensitive   = true
  description = <<EOF
    # save output with:
    export KUBECONFIG=$PWD/../jupyterhub/secrets/kubeconfig.yaml
    tofu output -raw kubeconfig > $KUBECONFIG
    chmod 600 $KUBECONFIG
    kubectl config rename-context kubernetes-admin@g4e g4e
    kubectl config use-context g4e
    EOF
}

# deploy cert-manager

provider "kubernetes" {
  host                   = ovh_cloud_project_kube.cluster.kubeconfig_attributes[0].host
  client_certificate     = base64decode(ovh_cloud_project_kube.cluster.kubeconfig_attributes[0].client_certificate)
  client_key             = base64decode(ovh_cloud_project_kube.cluster.kubeconfig_attributes[0].client_key)
  cluster_ca_certificate = base64decode(ovh_cloud_project_kube.cluster.kubeconfig_attributes[0].cluster_ca_certificate)
}

resource "kubernetes_namespace" "cert-manager" {
  metadata {
    name = "cert-manager"
  }
}

provider "helm" {
  kubernetes {
    host                   = ovh_cloud_project_kube.cluster.kubeconfig_attributes[0].host
    client_certificate     = base64decode(ovh_cloud_project_kube.cluster.kubeconfig_attributes[0].client_certificate)
    client_key             = base64decode(ovh_cloud_project_kube.cluster.kubeconfig_attributes[0].client_key)
    cluster_ca_certificate = base64decode(ovh_cloud_project_kube.cluster.kubeconfig_attributes[0].cluster_ca_certificate)
  }
}

resource "helm_release" "cert-manager" {
  name       = "cert-manager"
  namespace  = kubernetes_namespace.cert-manager.metadata[0].name
  repository = "https://charts.jetstack.io"
  chart      = "cert-manager"
  version    = "1.13.3"

  set {
    name  = "installCRDs"
    value = true
  }
  # match ClusterIssuer in g4e-hub chart
  set {
    name  = "ingressShim.defaultIssuerKind"
    value = "ClusterIssuer"
  }
  set {
    name  = "ingressShim.defaultIssuerName"
    value = "letsencrypt-prod"
  }
}

# registry

data "ovh_cloud_project_capabilities_containerregistry_filter" "registry_plan" {
  service_name = local.service_name
  # SMALL is 200GB
  # MEDIUM is 600GB
  # LARGE is 5TiB
  plan_name = "SMALL"
  region    = "GRA"
}

resource "ovh_cloud_project_containerregistry" "registry" {
  service_name = local.service_name
  plan_id      = data.ovh_cloud_project_capabilities_containerregistry_filter.registry_plan.id
  region       = data.ovh_cloud_project_capabilities_containerregistry_filter.registry_plan.region
  name         = "g4e"
}

# admin user (needed for harbor provider)
resource "ovh_cloud_project_containerregistry_user" "admin" {
  service_name = ovh_cloud_project_containerregistry.registry.service_name
  registry_id  = ovh_cloud_project_containerregistry.registry.id
  email        = "g4e-registry-admin@ovh.local"
  login        = "g4e-registry-admin"
}

 
 # now configure the registry via harbor itself
 provider "harbor" {
   url      = ovh_cloud_project_containerregistry.registry.url
   username = ovh_cloud_project_containerregistry_user.admin.login
   password = ovh_cloud_project_containerregistry_user.admin.password
 }
 
 resource "harbor_project" "registry" {
   name   = "g4e"
   public = true
 
   # FP 
   depends_on = [ovh_cloud_project_containerregistry.registry, ovh_cloud_project_containerregistry_user.admin]  # ATTEND
 
 }
 
 resource "random_password" "harbor_fpaul" {
   length  = 16
   special = true
 }
 resource "harbor_user" "fpaul" {
   username  = "fpaul"
   full_name = "Frederic PAUL"
   email     = "frederic.paul@ifremer.fr"
   password  = random_password.harbor_fpaul.result
   lifecycle {
     ignore_changes = [
       # only set initial password, allow changes
       password
     ]
   }
 }
 
 resource "harbor_project_member_user" "fpaul" {
   project_id = harbor_project.registry.id
   user_name  = harbor_user.fpaul.username
   role       = "developer"
 }
 
 resource "harbor_robot_account" "builder" {
   name        = "builder"
   description = "Image builder: push new images"
   level       = "project"
   permissions {
     access {
       action   = "push"
       resource = "repository"
     }
     access {
       action   = "pull"
       resource = "repository"
     }
     kind      = "project"
     namespace = harbor_project.registry.name
   }
 }
 
 resource "harbor_robot_account" "puller" {
   name        = "puller"
   description = "Pull access to images"
   level       = "project"
   permissions {
     access {
       action   = "pull"
       resource = "repository"
     }
     kind      = "project"
     namespace = harbor_project.registry.name
   }
 }
 
 resource "harbor_retention_policy" "builds" {
   # run retention policy on Saturday morning
   scope    = harbor_project.registry.id
   schedule = "0 0 7 * * 6"
   # rule {
   #   repo_matching        = "**"
   #   tag_matching         = "**"
   #   most_recently_pulled = 1
   #   untagged_artifacts   = false
   # }
   rule {
     repo_matching          = "**"
     tag_matching           = "**"
     n_days_since_last_pull = 30
     untagged_artifacts     = false
   }
   rule {
     repo_matching          = "**"
     tag_matching           = "**"
     n_days_since_last_push = 7
     untagged_artifacts     = false
   }
 }
resource "harbor_garbage_collection" "gc" {
  # run garbage collection on Sunday morning
  # try to make sure it's not run at the same time as the retention policy
  schedule        = "0 0 7 * * 0"
  delete_untagged = true
}

# registry outputs

output "registry_url" {
  value       = ovh_cloud_project_containerregistry.registry.url
  description = <<EOF
    # login to docker registry with:
    echo $(tofu output -raw registry_builder_token) | docker login $(tofu output -raw registry_url) --username $(tofu output -raw registry_builder_name) --password-stdin
    EOF
}

output "registry_admin_login" {
  value     = ovh_cloud_project_containerregistry_user.admin.login
  sensitive = true
}

output "registry_admin_password" {
  value     = ovh_cloud_project_containerregistry_user.admin.password
  sensitive = true
}

output "registry_user_fpaul" {
  value     = "${harbor_user.fpaul.username}:${harbor_user.fpaul.password}"
  sensitive = true
}


output "registry_builder_name" {
  value     = harbor_robot_account.builder.full_name
  sensitive = true
}

output "registry_builder_token" {
  value     = harbor_robot_account.builder.secret
  sensitive = true
}

output "registry_puller_name" {
  value     = harbor_robot_account.puller.full_name
  sensitive = true
}
output "registry_puller_token" {
  value     = harbor_robot_account.puller.secret
  sensitive = true
}
