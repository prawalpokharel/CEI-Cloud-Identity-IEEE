B=http://frontend
PID=OLJCESPC7Z
CK='--max-time 15 -s -o /dev/null -w %{http_code}'
J1=$(mktemp)
h=$(curl $CK -c $J1 $B/)
br=$(curl $CK -c $J1 $B/product/$PID)
J2=$(mktemp); curl -s -o /dev/null -c $J2 $B/ >/dev/null 2>&1
ad=$(curl $CK -c $J2 -b $J2 -d "product_id=$PID&quantity=1" $B/cart)
J3=$(mktemp); curl -s -o /dev/null -c $J3 $B/ >/dev/null 2>&1; curl -s -o /dev/null -c $J3 -b $J3 -d "product_id=$PID&quantity=1" $B/cart >/dev/null 2>&1
vc=$(curl $CK -c $J3 -b $J3 $B/cart)
J4=$(mktemp); curl -s -o /dev/null -c $J4 $B/ >/dev/null 2>&1; curl -s -o /dev/null -c $J4 -b $J4 -d "product_id=$PID&quantity=1" $B/cart >/dev/null 2>&1
co=$(curl --max-time 20 -s -o /dev/null -w %{http_code} -c $J4 -b $J4 -d "email=a@b.com&street_address=1600+A&zip_code=94043&city=MV&state=CA&country=USA&credit_card_number=4432801561520454&credit_card_expiration_month=1&credit_card_expiration_year=2039&credit_card_cvv=672" $B/cart/checkout)
echo "$h $br $ad $vc $co"
rm -f $J1 $J2 $J3 $J4
