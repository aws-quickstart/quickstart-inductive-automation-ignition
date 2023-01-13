# quickstart-inductive-automation-ignition
## Ignition by Inductive Automation on the AWS Cloud

This Quick Start automatically deploys a highly available, production-ready Ignition server on the Amazon Web Services (AWS) Cloud in about 30 minutes, into a configuration of your choice.

Ignition is server software that acts as the hub for everything on your plant floor for total system integration. No matter what brand, model, or platform, it talks to your plant-floor equipment just as naturally as it talks to SQL databases, seamlessly bridging the gap between production and IT.

Ignition comes with everything you need to create any kind of industrial application for desktops, industrial displays and mobile screens. The included Ignition Designer combines a rich component library, easy data-binding, as well as powerful tools for drawing and scripting, into one fully-integrated development environment.

This Quick Start uses AWS CloudFormation templates to deploy Ignition into a virtual private cloud (VPC) in your AWS account. You can build a new VPC for Ignition, or deploy the software into your existing VPC. The automated deployment provisions a redundant pair of Amazon Elastic Compute Cloud (Amazon EC2) instances running Ignition and an Aurora DB cluster that includes two DB readers and one DB writer. You can also use the AWS CloudFormation templates as a starting point for your own implementation.

![Quick Start architecture for Ignition on AWS](./images/architecture_standalone_diagram.png)

For architectural details, step-by-step instructions, and customization options, see the [deployment guide](https://aws-quickstart.github.io/quickstart-inductive-automation-ignition/).

To post feedback, submit feature ideas, or report bugs, use the **Issues** section of this GitHub repo. 

To submit code for this Quick Start, see the [AWS Quick Start Contributor's Kit](https://aws-quickstart.github.io/).