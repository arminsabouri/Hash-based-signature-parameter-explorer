# Serve the site locally at http://localhost:8000
run:
    python3 -m http.server 8000

# Check the scheme figures against FIPS 205 and the SHRINCS BIP
test:
    node --test 'test/*.test.js'
