# FullStack-Blogging-App

# Infrastructure & Installation (AWS EC2 + K8s + DevOps Tools)

## 1.AWS Setup
1. Default vpc
2. **Security Group:** Default SG with port 8 open
3. Create Instancess 7 (t2.medium, 25gb)
- Master Node
- Slave-1
- Slave-2
- SonarQube
- Nexus
- Monitor
- Jenkins (t2 large,30)

---

## Setup AWS EKS Cluster by Terraform

### 1. AWS CLI Install
Donload and install AWS CLI for connect with aws cloud

```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
aws --version
```
**Expected output:**

```text
aws-cli/2.x.x Python/3.x.x Linux/...
```

### 2. Configure AWS CLI
You need AWS credentials to use the CLI. Run:

```bash
aws configure
```

Provide the following when prompted:

- AWS Access Key ID
- AWS Secret Access Key
- Default region (e.g. `ap-southeast-1`)
- Output format (`json` recommended)

### 3. Terraform Installation on Ubuntu  
**Method 1: Official APT Repository (Recommended for Production)**

```bash
# Install prerequisites
sudo apt install -y gnupg software-properties-common curl

# Add HashiCorp GPG key
curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg

# Add the official HashiCorp Linux repo
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | \
sudo tee /etc/apt/sources.list.d/hashicorp.list

# Update and install Terraform
sudo apt update
sudo apt install terraform -y

# Verify installation
terraform -version

```
**Method 2: Snap (Quick Setup, Not Always Latest Version)**

```bash
sudo snap install terraform --classic

```
### 4. EKS Cluster Create by Terraform

**Terraform Folder create**

```bash
mkdir terra
cd terra
```
**Terraform File Create**

1. Main File create
```bash
vim main.tf
```
Copy configure file

```bash
provider "aws" {
  region = "ap-southeast-1"
}

resource "aws_vpc" "abrahimcse_vpc" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "abrahimcse-vpc"
  }
}

resource "aws_subnet" "abrahimcse_subnet" {
  count = 2
  vpc_id                  = aws_vpc.abrahimcse_vpc.id
  cidr_block              = cidrsubnet(aws_vpc.abrahimcse_vpc.cidr_block, 8, count.index)
  availability_zone       = element(["ap-southeast-1a", "ap-southeast-1b"], count.index)
  map_public_ip_on_launch = true

  tags = {
    Name = "abrahimcse-subnet-${count.index}"
  }
}

resource "aws_internet_gateway" "abrahimcse_igw" {
  vpc_id = aws_vpc.abrahimcse_vpc.id

  tags = {
    Name = "abrahimcse-igw"
  }
}

resource "aws_route_table" "abrahimcse_route_table" {
  vpc_id = aws_vpc.abrahimcse_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.abrahimcse_igw.id
  }

  tags = {
    Name = "abrahimcse-route-table"
  }
}

resource "aws_route_table_association" "a" {
  count          = 2
  subnet_id      = aws_subnet.abrahimcse_subnet[count.index].id
  route_table_id = aws_route_table.abrahimcse_route_table.id
}

resource "aws_security_group" "abrahimcse_cluster_sg" {
  vpc_id = aws_vpc.abrahimcse_vpc.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "abrahimcse-cluster-sg"
  }
}

resource "aws_security_group" "abrahimcse_node_sg" {
  vpc_id = aws_vpc.abrahimcse_vpc.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "abrahimcse-node-sg"
  }
}

resource "aws_eks_cluster" "abrahimcse" {
  name     = "abrahimcse-cluster"
  role_arn = aws_iam_role.abrahimcse_cluster_role.arn

  vpc_config {
    subnet_ids         = aws_subnet.abrahimcse_subnet[*].id
    security_group_ids = [aws_security_group.abrahimcse_cluster_sg.id]
  }
}

resource "aws_eks_node_group" "abrahimcse" {
  cluster_name    = aws_eks_cluster.abrahimcse.name
  node_group_name = "abrahimcse-node-group"
  node_role_arn   = aws_iam_role.abrahimcse_node_group_role.arn
  subnet_ids      = aws_subnet.abrahimcse_subnet[*].id

  scaling_config {
    desired_size = 3
    max_size     = 3
    min_size     = 3
  }

  instance_types = ["t2.large"]

  remote_access {
    ec2_ssh_key = var.ssh_key_name
    source_security_group_ids = [aws_security_group.abrahimcse_node_sg.id]
  }
}

resource "aws_iam_role" "abrahimcse_cluster_role" {
  name = "abrahimcse-cluster-role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "eks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "abrahimcse_cluster_role_policy" {
  role       = aws_iam_role.abrahimcse_cluster_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role" "abrahimcse_node_group_role" {
  name = "abrahimcse-node-group-role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "abrahimcse_node_group_role_policy" {
  role       = aws_iam_role.abrahimcse_node_group_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "abrahimcse_node_group_cni_policy" {
  role       = aws_iam_role.abrahimcse_node_group_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "abrahimcse_node_group_registry_policy" {
  role       = aws_iam_role.abrahimcse_node_group_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

```
2. Variable file create
```bash
vim variable.tf
```
copy and past
```bash
variable "ssh_key_name" {
  description = "The name of the SSH key pair to use for instances"
  type        = string
  default     = "hsms-stg-common"
}
```
3. Output File Create
```bash
vim output.tf
```
copy and past

```bash
output "cluster_id" {
  value = aws_eks_cluster.abrahimcse.id
}

output "node_group_id" {
  value = aws_eks_node_group.abrahimcse.id
}

output "vpc_id" {
  value = aws_vpc.abrahimcse_vpc.id
}

output "subnet_ids" {
  value = aws_subnet.abrahimcse_subnet[*].id
}

```
4. Run Terraform File for create eks

```bash
terraform init
terraform plan
terraform validate
terraform apply --auto-approve
```
5. Connect with EKS Cluster
```bash
aws eks --region ap-southeast-1 update-kubeconfig --name abrahimcse-cluster
```
6. Install Kubect and check nodes
```bash
sudo snap install kubectl --classic
kubectl get nodes
```
---
### 5. RBAC Setup (Master Node)
1. Create cluster service account
  user-1 , role-1 (cluster admin access)
  user-2 , role-2 (good level of access)
  user-3 , role-3 (read only access)

**Create folder for RBAC**

```bash
cd ..
mkdir rbac
cd rbac
```
**Create Namespace**

```yml
kubectl create ns webapps
```
**Create Service Account**

```bash
vi svc.yaml
```
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: jenkins
  namespace: webapps
```
```bash
kubectl apply -f svc.yaml
```
**Create Role**

```bash
vi role.yaml
```
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-role
  namespace: webapps
rules:
  - apiGroups:
        - ""
        - apps
        - autoscaling
        - batch
        - extensions
        - policy
        - rbac.authorization.k8s.io
    resources:
      - pods
      - secrets
      - componentstatuses
      - configmaps
      - daemonsets
      - deployments
      - events
      - endpoints
      - horizontalpodautoscalers
      - ingress
      - jobs
      - limitranges
      - namespaces
      - nodes
      - pods
      - persistentvolumes
      - persistentvolumeclaims
      - resourcequotas
      - replicasets
      - replicationcontrollers
      - serviceaccounts
      - services
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
```
```bash
kubectl apply -f role.yaml
```
**Bind Role to Service Account**

```bash
vi bind.yaml
```
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-rolebinding
  namespace: webapps 
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: app-role 
subjects:
- namespace: webapps 
  kind: ServiceAccount
  name: jenkins 

```
```bash
kubectl apply -f bind.yaml
```
**Create Secret to Get Service Account Token**

```bash
vi sec.yaml 
```
```yaml
apiVersion: v1
kind: Secret
type: kubernetes.io/service-account-token
metadata:
  name: mysecretname
  annotations:
    kubernetes.io/service-account.name: jenkins
```
```bash
kubectl apply -f sec.yaml -n webapps
```
**Collect Token and save into jenkins credential**
```bash
kubectl describe secret mysecretname -n webapps
```
**Create Secret for Docker Registry (DockerHub)**
```bash
kubectl create secret docker-registry regcred \
  --docker-server=https://index.docker.io/v1/ \
  --docker-username=abrahimcse \
  --docker-password=<your_dockerhub_password> \
  --docker-email=abrahimcse@gmail.com \
  --namespace=webapps

```
**To verify the secret:**
```bash
kubectl get secret regcred --namespace=webapps --output=yaml
```
**Check kubeconfig Info**

```bash
cd ~/.kube
ls
cat config
```
✅ Use `server: IP` from this config if needed in `deployment-service.yaml` or `Jenkins setup`.

---

# Other server Ready

## 1. SonarQube Server Setup

### Step 1: Install Docker and Enable Rootless Mode

```bash
sudo apt update
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

sudo apt-get install -y uidmap
dockerd-rootless-setuptool.sh install
```
### Step 2: Run SonarQube Docker Container
 
```bash
docker run -d --name Sonar -p 9000:9000 sonarqube:lts-community
```
- Access SonarQube: `http://<server_ip>:9000/`

- Default Credentials:

  - **Username:** `admin`

  - **Password:** `admin`

### Step 3: Generate Authentication Token

1. Go to: `**Administration > Security > Users > Tokens**`

2. Create a new token:

  - **Name:** `sonar-token`

3. Click **Generate** and **copy the token**

### Step 4: Configure Webhook for Jenkins

1. Navigate to: `**Administration > Configuration > Webhooks**`

2. Click Create Webhook

  - **Name:** `jenkins`

  - **URL:** `http://<jenkins_public_ip>:8080/sonarqube-webhook/`

**📌 Note:** Ensure Jenkins is reachable from SonarQube server.

![webhook Image]()

---

## 2. Nexus Server

### Step 1: Install Docker and Enable Rootless Mode

```bash
sudo apt update
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

sudo apt-get install -y uidmap
dockerd-rootless-setuptool.sh install
```
### Step 2: Run Nexus Docker Container

```bash
docker run -d --name Nexus -p 8081:8081 sonatype/nexus3
```

### Step 3: Retrieve Admin Password

```bash
docker ps
docker exec -it <container id> sh

cat sonatype-work/nexus3/admin.password
```
- **Access Nexus:** `http://<server_ip>:8081/`

- **Username:** admin

- **Password:** (copy from the file above)


`***check Enable anonymous access***`(if needed for testing or open read access)

Browser
 - maven-releases (copy)
 - maven-snapshots (copy)
 
### Step 4: Update Your Maven pom.xml

Modify your `pom.xml` file with the Nexus repository endpoints:

```xml
 	 <distributionManagement>
        <repository>
            <id>maven-releases</id>
            <url>http://18.143.91.119:8081/repository/maven-releases/</url> 
        </repository>
        <snapshotRepository>
            <id>maven-snapshots</id>
            <url>http://18.143.91.119:8081/repository/maven-snapshots/</url>
        </snapshotRepository>
    </distributionManagement>
```
---
## 3. Jenkins Server Setup (CI/CD Pipeline with SonarQube, Nexus, Docker, Kubernetes)

### Step 1: Install Docker (with Rootless Mode)

```bash
sudo apt update
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

sudo apt-get install -y uidmap
dockerd-rootless-setuptool.sh install
```
**Verify Docker:**
```bash
docker --version
```

### Step 2: Install Trivy (Security Vulnerability Scanner)
[Official docks:](https://trivy.dev/v0.63/getting-started/installation/)

```bash
vim trivy.sh
```
**Paste into `trivy.sh:`**

```bash
sudo apt-get install wget gnupg
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy -y
```
**Run script:**

```bash
sudo chmod +x trivy.sh
./trivy.sh
trivy --version
```
### Step 3: Install Jenkins (Debian/Ubuntu)

```bash
vim jenkin.sh
```
**Paste into `jenkin.sh:`**

```bash

#!/bin/bash

# Install OpenJDK 17 JRE Headless
sudo apt install openjdk-17-jre-headless -y

# Download Jenkins GPG key
sudo wget -O /usr/share/keyrings/jenkins-keyring.asc \
  https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key

# Add Jenkins repository to package manager sources
echo deb [signed-by=/usr/share/keyrings/jenkins-keyring.asc] \
  https://pkg.jenkins.io/debian-stable binary/ | sudo tee \
  /etc/apt/sources.list.d/jenkins.list > /dev/null

# Update package manager repositories
sudo apt-get update

# Install Jenkins
sudo apt-get install jenkins -y

```
**Run it:**

```bash
chmod +x jenkin.sh
./jenkin.sh
```
**Access Jenkins:**
- **URL:** `http://<server_ip>:8080`

- Initial password:

```bash
sudo cat /var/lib/jenkins/secrets/initialAdminPassword
```

### Step 4: Install kubectl on Jenkins Server
```
vi kubelet.sh
```
**Paste into `kubelet.sh`**

```bash
#!/bin/bash
curl -o kubectl https://amazon-eks.s3.us-west-2.amazonaws.com/1.19.6/2021-01-05/bin/linux/amd64/kubectl
chmod +x ./kubectl
sudo mv ./kubectl /usr/local/bin
kubectl version --short --client
```
**Run it:**

```bash
chmod +x kubelet.sh
./kubelet.sh
```
### Step 5: Add Jenkins to Docker Group

```bash
sudo usermod -aG docker jenkins
sudo systemctl restart jenkins
```

## Jenkins Configuration

### Step 6: Install Required Plugins

**Navigate: `Dashboard > Manage Jenkins > Plugins > Available Plugins`**

**Install:**

  ✅ Docker
  ✅ Docker Pipeline
  ✅ Kubernetes
  ✅ Kubernetes CLI
  ✅ Kubernetes Client API
  ✅ Kubernetes Credentials
  ✅ Prometheus Metrics
  ✅ Pipeline: Stage View
  ✅ Pipeline Maven Integration
  ✅ Maven Integration
  ✅ SonarQube Scanner
  ✅ Config File Provider
  ✅ Eclipse Temurin installer

*📝 Restart Jenkins after plugin installation.*

![Plugins]() 

### Step 7: Global Tool Configuration

**Navigate: `Dashboard > Manage Jenkins > Tools`**

- **JDK:**

  - Name: `jdk17`
  - Check "Install automatically"
  - Source: `Adoptium.net`
  - Version: `jdk-17.0.9+9`

- **SonarQube Scanner:**

  - Name: `sonar-scanner`
  - Version: `latest`

- **Maven:**

  - Name: `maven3`
  - Version: `3.6.1`

- **Docker:**

  - Name: `docker`
  - Install Automatically

### Step 8: Credentials Setup

**Navigate: `Manage Jenkins > Credentials > System > Global > Add Credentials`**

- **github**
  - username : `guthub-username`
  - secret : `github-token`
  - ID : `git-cred`
  - Description : `git-cred`

- **sonarqube**
  - Kind : `secret text`
  - secret: `generated token(sonar-token)`
  - ID : `sonar-token`
  - Description : `sonar-token`

- **Docker Hub**
  - username: dockerhub_username
  - pass : dockerhub_password
  - ID : docker-cred
  - Description : docker-cred

- **K8s-Cluster**
  - Kind : `secret text`
  - secret: `token` (kubectl describe secret mysecretname -n webapps)
  - ID : `k8-cred`
  - Description : `k8-cred`

### Step 9: Add Maven Settings File (for Nexus)

**Navigate: `Manage Jenkins > Managed Files > Add a New Config`**

- Type: **Global Maven settings.xml**

- ID: `global-settings`

**Paste:**

```xml
<settings>
  <servers>
    <server>
      <id>maven-releases</id>
      <username>nexus_username</username>
      <password>nexus_password</password>
    </server>
    <server>
      <id>maven-snapshots</id>
      <username>nexus_username</username>
      <password>nexus_password</password>
    </server>
  </servers>
</settings>

```
### Step 10: Add SonarQube Server Info

**Navigate: `Manage Jenkins > System > SonarQube Servers`**

- Name: `sonar`

- Server URL: `http://<sonar_server_ip>:9000`
  
  - **like: http://54.169.71.209:9000**

- Token: `sonar-token` (from credentials)

### Step 11: Create a New Pipeline Job

**➤ Create Job**
- Go to Jenkins Dashboard

- Click `New Item`

- Name: `BloggingApp`

- Type: `Pipeline`

- Click `OK`

**➤ Basic Configuration**

- Discard Old Builds:
  
  - Max # of builds: `2`

- Pipeline Definition:

  - Choose: `Pipeline script`

```groovy
pipeline {
    agent any

    stages {
        stage('Hello') {
            steps {
                echo 'Hello World'
            }
        }
    }
}

```
** ➤ Jenkins Declarative Pipeline Syntax (GUI to Script Mapping)**

- Pipeline Syntax
  
- Sample Step
  - git : Git
    
    - Repository URL : github url
    - Branch : main
    - Credential : select id

```groovy
 git branch: 'main', credentialsId: 'git-cred', url: 'https://github.com/abrahimcse/FullStack-Blogging-App.git'
```

- Sample Step
  withSonarQubeEnv: Prepare SonarQube Scanner environment

    server token : sonar-token

```groovy
withSonarQubeEnv(credentialsId: 'sonar-token') {
}
```
- Sample Step
  withKubeConfig: COnfigure Kubernets CLI (kubectl)
    
    - Credential : `k8-cred` 
    - kubernetes server endpoint : <eks api server endpoint from aws>
    - cluster name : abrahimcse-cluster
    - namespace : webapps

```groovy
 withKubeConfig(caCertificate: '', clusterName: 'abrahimcse-cluster', contextName: '', credentialsId: 'k8-cred', namespace: 'webapps', restrictKubeConfigAccess: false, serverUrl: 'https://< >.ap-southes-1.eks.amazonaws.com')
```

**Pipeline Configuration **

Here’s a quick `visual stage flow` from your pipeline for clarity:

1. Git Checkout → 
2. Compile →
3. Unit Test →
4. Trivy Scan →
5. SonarQube Analysis →
6. Quality Gate Check →
7. Build JAR →
8. Deploy to Nexus →
9. Docker Image Build →
10. Push to DockerHub
11. Deploy to Kubernetes →
12. Verify the Deployment →

```groovy
pipeline {
    agent any
    
    tools {
        jdk 'jdk17'
        maven 'maven3'
    }
    
    environment {
        SCANNER_HOME = tool 'sonar-scanner'
    }

    stages {
        stage('Git Checkout') {
            steps {
               git branch: 'main', credentialsId: 'git-cred', url: 'https://github.com/abrahimcse/FullStack-Blogging-App.git'
            }
        }
        stage('Compile') {
            steps {
                sh "mvn compile"
            }
        }
        
        stage('Test') {
            steps {
                sh "mvn test"
            }
        }
        
        stage('File System Scan') {
            steps {
                sh "trivy fs --format table -o trivy-fs-report.html ."
            }
        }
        stage('SonarQube Analsyis') {
            steps {
                withSonarQubeEnv('sonar') {
                    sh ''' $SCANNER_HOME/bin/sonar-scanner -Dsonar.projectName=bloggingapp -Dsonar.projectKey=bloggingapp \
                            -Dsonar.java.binaries=. '''
                }
            }
        }
        stage('Quality Gate') {
            steps {
                script {
                  waitForQualityGate abortPipeline: false, credentialsId: 'sonar-token' 
                }
            }
        }
        stage('Build') {
            steps {
                sh "mvn package"
            }
        }
        stage('Publish To Nexus') {
            steps {
            withMaven(globalMavenSettingsConfig: 'global-settings', jdk: 'jdk17', maven: 'maven3', mavenSettingsConfig: '', traceability: true) {
                    sh "mvn deploy"
                }
            }
        }
        stage('Build & Tag Docker Image') {
            steps {
               script {
                   withDockerRegistry(credentialsId: 'docker-cred', toolName: 'docker') {
                            sh "docker build -t abrahimcse/bloggingapp:latest ."
                    }
               }
            }
        }
        stage('Docker Image Scan') {
            steps {
                sh "trivy image --format table -o trivy-image-report.html abrahimcse/bloggingapp:latest "
            }
        }
        stage('Push Docker Image') {
            steps {
               script {
                   withDockerRegistry(credentialsId: 'docker-cred', toolName: 'docker') {
                            sh "docker push abrahimcse/bloggingapp:latest"
                    }
               }
            }
        }
        stage('Deploy To Kubernetes') {
            steps {
                withKubeConfig(caCertificate: '', clusterName: 'abrahimcse-cluster', contextName: '', credentialsId: 'k8-cred', namespace: 'webapps', restrictKubeConfigAccess: false, serverUrl: 'https://< >.ap-southes-1.eks.amazonaws.com') {
                      sh "kubectl apply -f deployment-service.yaml"
                }
            }
        }
        
        stage('Verify the Deployment') {
            steps {
                withKubeConfig(caCertificate: '', clusterName: 'abrahimcse-cluster', contextName: '', credentialsId: 'k8-cred', namespace: 'webapps', restrictKubeConfigAccess: false, serverUrl: 'https://< >.ap-southes-1.eks.amazonaws.com') {
                        sh "kubectl get pods -n webapps"
                        sh "kubectl get svc -n webapps"
                }
            }
        }

    post {
    always {
        script {
            def jobName = env.JOB_NAME
            def buildNumber = env.BUILD_NUMBER
            def pipelineStatus = currentBuild.result ?: 'UNKNOWN'
            def bannerColor = pipelineStatus.toUpperCase() == 'SUCCESS' ? 'green' : 'red'

            def body = """
                <html>
                <body>
                <div style="border: 4px solid ${bannerColor}; padding: 10px;">
                <h2>${jobName} - Build ${buildNumber}</h2>
                <div style="background-color: ${bannerColor}; padding: 10px;">
                <h3 style="color: white;">Pipeline Status: ${pipelineStatus.toUpperCase()}</h3>
                </div>
                <p>Check the <a href="${BUILD_URL}">console output</a>.</p>
                </div>
                </body>
                </html>
            """

            emailext (
                subject: "${jobName} - Build ${buildNumber} - ${pipelineStatus.toUpperCase()}",
                body: body,
                to: 'abrahim.ctech@gmail.com',
                from: 'jenkins@example.com',
                replyTo: 'jenkins@example.com',
                mimeType: 'text/html',
                attachmentsPattern: 'trivy-image-report.html'
            )
        }
      }       
    }   
}

```
---
## 📧 Jenkins Email Notification Setup (Gmail SMTP)

You'll configure Jenkins to send email notifications using Gmail's SMTP service.

### Step 1: Generate Gmail App Password

1. Go to https://myaccount.google.com/apppasswords

2. Navigate to:
  - `Security` → `2-Step Verification` → Enable it (if not already)
  - Scroll down to `App Passwords`

3. Select:
  - App: `Mail`
  - Device: `Jenkins` (or any name)
**password:** 
4. ✅ **Copy the generated password **(you’ll use this in Jenkins configuration)

### Step 2: Configure Jenkins Email Notification

**Go to Jenkins: `manage jenkins > system`**

**1. Extended E-mail Notification**
  - SMTP server: smtp.gmail.com
  - SMTP POrt : 465

🔽 Click on Advanced
  - Check Use SSL
  - ✅ Add Credentials:
    - **Kind :** Username with password
    - **Username :** `abrahim.ctech@gmail.com`
    - **Password:** `ubdh oyoe hirs wudv`
    - **ID :** `mail-cred`
  - Select the added credential `abrahim.ctech@gmail.com`(mail-cred)

**2. E-mail Notification**
- SMTP Server: `smtp.gmail.com`

🔽 Click **Advanced**
- ✅ Check Use SSL
- SMTP Port: 465
- ✅ Check Use SMTP Authentication
  - Username: `abrahim.ctech@gmail.com`
  - Password: `ubdh oyoe hirs wudv`

**3. Test the Configuration**
- Scroll down to the **Test configuration** section
- Enter your email: `abrahim.ctech@gmail.com`
- Click **Test Configuration**

You should receive a **test email** if everything is configured properly.

---
## Monitoring Setup: Prometheus + Grafana + Exporters

Ensure your system is updated first:

```bash
sudo apt update -y
```
### Step 1: Install Prometheus

**🔗 [Download Prometheus](https://prometheus.io/download)**

```bash
wget https://github.com/prometheus/prometheus/releases/download/v3.5.0-rc.0/prometheus-3.5.0-rc.0.linux-amd64.tar.gz

ls
tar -xvf prometheus-3.5.0-rc.0.linux-amd64.tar.gz
rm -rf prometheus-3.5.0-rc.0.linux-amd64.tar.gz
mv prometheus-3.5.0-rc.0.linux-amd64 prometheus
cd prometheus
ls 
./prometheus &
```
**🌐 Access Prometheus:** `http://<public_ip>:9090`

###  Step 2: Install Grafana

**🔗 [Download Grafana Enterprise](https://grafana.com/grafana/download)**

```bash
sudo apt-get install -y adduser libfontconfig1 musl
wget https://dl.grafana.com/enterprise/release/grafana-enterprise_12.0.2_amd64.deb
sudo dpkg -i grafana-enterprise_12.0.2_amd64.deb

sudo systemctl start grafana-server
```
**🌐 Access Grafana:** `http://<public_ip>:3000`
**👤 Default Login:**
- Username: `admin`
- Password: `admin`

### Step 3: Setup Blackbox Exporter
**🔗 [Download Blackbox Exporter](https://prometheus.io/download/#blackbox_exporter)**

```bash
wget https://github.com/prometheus/blackbox_exporter/releases/download/v0.27.0/blackbox_exporter-0.27.0.linux-amd64.tar.gz

tar -xvf blackbox_exporter-0.27.0.linux-amd64.tar.gz
rm -rf blackbox_exporter-0.27.0.linux-amd64.tar.gz
mv blackbox_exporter-0.27.0.linux-amd64 blackbox_exporter
cd blackbox_exporter
ls ./backbox_exporter &
```
**🌐 Access Blackbox Exporter:** `http://<public_ip>:9115`

**Configure [prometheus.yml](https://github.com/prometheus/blackbox_exporter) to include Blackbox:**

```bash
cd ~/prometheus
vim prometheus.yml

```
**Add the following job:**

```yml
  - job_name: 'blackbox'
    metrics_path: /probe
    params:
      module: [http_2xx]  # Look for a HTTP 200 response.
    static_configs:
      - targets:
        - http://prometheus.io    # Target to probe with http.
        - http://example.com:8080 # Target to probe with http on port 8080.
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: 127.0.0.1:9115  # The blackbox exporter's real hostname:port.

```
**Restart Prometheus:**

```bash
pgrep prometheus
kill id
./prometheus & 

```
### Step 4: Install Node Exporter (on Jenkins server)

**🔗 [Download Node Exporter](https://prometheus.io/download/#node_exporter)**

```bash
wget https://github.com/prometheus/node_exporter/releases/download/v1.9.1/node_exporter-1.9.1.linux-amd64.tar.gz
ls 
tar -xvf node_exporter-1.9.1.linux-amd64.tar.gz
ls
rm rf node_exporter-1.9.1.linux-amd64.tar.gz
mv node_exporter-1.9.1.linux-amd64.tar.gz node_exporter
cd node_exporter
ls
./node_exporter &
```
**🌐 Node Exporter Port: `http://<jenkins_server_ip>:9100`**

**Add Node Exporter and Jenkins Job to prometheus.yml**

```
cd prometheus
ls 
vim prometheus.yml
```
```yml
  - job_name: 'node_exporter'
    static_configs:
      - targets: ['<jenkins_server_ip>:9100']

  - job_name: 'jenkins'
    metrics_path: /prometheus
    static_configs:
      - targets: ['<jenkins_server_ip>:8080']
```
**Restart Prometheus:**

```bash
pgrep prometheus
kill id
./prometheus &

```
### Step 5: Connect Grafana with Prometheus
1. Go to Grafana UI:  `Grafana > Connections > Data sources > Add data source`
2. Select **Prometheus** from the list.
3. Fill in the details:
   - **Name**: `Prometheus` (or any preferred name)
   - **URL**:
     ```
     http://<PROMETHEUS_SERVER_IP>:9090
     ```
4. Scroll down and click **Save & Test**.  
   You should see a message like: `Data source is working`.

### Step 6: Import Dashboards
1. Navigate to:  `Dashboard > Import`
2. Paste one of the dashboard IDs listed below.
3. Click **Load**.
4. Select your **Prometheus** data source.
5. Click **Import** to finish.

| Dashboard Name       | Dashboard ID |
|----------------------|--------------|
| 🔍 Blackbox Exporter | `7587`       |
| 🖥️ Node Exporter     | `1860`       |

---