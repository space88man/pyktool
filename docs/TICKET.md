# Tickets

## Tickets

* [T-1]: add support for file names like jks:abcd, to indicate
  the file type

        #
        pyktool dump jks:keystore changeit
        pyktool convert jks:keystore changeit bks:keystore2 changeit
   
       
## flake8

```
flake8 --ignore E501,F405,F401 pyktool/sun_crypto.py 
```
