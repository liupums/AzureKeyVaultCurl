sudo apt install -y build-essential   libssl-dev   libcurl4-openssl-dev   libjson-c-dev   cmake   nginx
cd opt
echo $1
git clone https://pop:$1@github.com/liupums/AkvOpensslEngine.git
cd AkvOpensslEngine/src
mkdir build
cd build
cmake ..
make
openssl version -a | grep ENGINESDIR
sudo cp e_akv.so /usr/lib/x86_64-linux-gnu/engines-1.1/e_akv.so
openssl engine -vvv -t e_akv
cp ../openssl.cnf .
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
az login --identity --allow-no-subscriptions
az keyvault key create --vault-name BuildTestKeyVault --name testrsakey --kty RSA --size 2048
openssl req -new -x509 -config openssl.cnf -engine e_akv -keyform engine -key vault:BuildTestKeyVault:testrsakey -out cert.pem
sudo cp cert.pem /etc/ssl/certs/contoso_rsa_cert.cer
sudo cp ../nginx.conf /etc/nginx/nginx.conf
sudo cp ../default /etc/nginx/sites-available/default
sudo /etc/init.d/nginx restart
curl -k https://localhost:443 -vv
