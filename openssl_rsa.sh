openssl genrsa -out $1.pem 1024
#openssl rsa -in $1.pem -pubout > $1.pub
openssl rsa -in $1.pem -pubout -out $1.pub
