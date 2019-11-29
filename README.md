# Sisifo Project
[![License](http://img.shields.io/:license-mit-blue.svg?style=flat-square)](http://badges.mit-license.org)

Integration Continue Tool (CI/CD) to determine if an application meets minimum security standards before being deployed in a production environment.

## Index

Sisifo is structured in different modules that make it flexible to configure and run it.

- **Sisifo** -- Sisifo project templates
    > [sisifo](https://github.com/2-DAST-2-CONTINUOUS/sisifo/tree/master/sisifo)

- **DAST Tools** -- Different tools that are launched in the process that makes Sisifo
    > [dast-tools](https://github.com/2-DAST-2-CONTINUOUS/sisifo/tree/master/dast-tools)
    
- **Application Webs Demos** -- Web applications used to test the Sisifo process
    > [demos](https://github.com/2-DAST-2-CONTINUOUS/sisifo/tree/master/demos)
    
- **Container Template** -- GitLab CI Template to registry a container image of developed application in GitLab Registry
    > [container-template](https://github.com/2-DAST-2-CONTINUOUS/sisifo/tree/master/container-template)

- **Sisifo Evaluator** -- Java Application whose aim is to analyze Dast Tools reports and evaluate depending on the criteria     previously established by the auditor whether the application can be deployed in the production environment or not. 
    > [evaluator](https://github.com/2-DAST-2-CONTINUOUS/sisifo/tree/master/evaluator)
    
## Authors
* **Jorge Gil Fernández** - [jorgeInno](https://github.com/PurpleBooth)
* **Ismael Requena Andreu** - [Ismaibz](https://github.com/PurpleBooth)
* **Víctor Alexander Parrales** - [Alexander-047](https://github.com/PurpleBooth)
* **José Antonio Maldonado Jiménez** - [guajar](https://github.com/PurpleBooth)

## License
This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details
