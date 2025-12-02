#!/usr/bin/env bash
set -euo pipefail

#KEYDIR="./keys_unlimited"
#VALIDITY=''

KEYDIR="./keys_limited"
VALIDITY='-V +364d'


rm -rf $KEYDIR
mkdir -p $KEYDIR

signers=(
  "ecdsa_nistp256"
  "ecdsa_nistp384"
  "ecdsa_nistp521"
  "ed25519"
  "rsa_sha256"
  "rsa_sha512"
)

ssh-keygen -t ecdsa -b 256 -C "" -f $KEYDIR/ecdsa_nistp256 -N ""
ssh-keygen -t ecdsa -b 384 -C "" -f $KEYDIR/ecdsa_nistp384 -N ""
ssh-keygen -t ecdsa -b 521 -C "" -f $KEYDIR/ecdsa_nistp521 -N ""
ssh-keygen -t ed25519 -C "" -f $KEYDIR/ed25519 -N ""
ssh-keygen -t rsa -b 4096 -C "" -f $KEYDIR/rsa_sha256 -N ""
ssh-keygen -t rsa -b 4096 -C "" -f $KEYDIR/rsa_sha512 -N ""

subjects=("${signers[@]}")

zserial=1




for signer in "${signers[@]}"; do
  signer_priv="${KEYDIR}/${signer}"
  if [ ! -f "$signer_priv" ]; then
    echo "WARN: private key '$signer_priv' missing, skipping."
    continue
  fi

  for subject in "${subjects[@]}"; do
    # skip self signed
    if [ "$signer" = "$subject" ]; then
      continue
    fi

    subject_pub="${KEYDIR}/${subject}.pub"
    if [ ! -f "$subject_pub" ]; then
      echo "WARN: public key '$subject_pub' not present, skpping $signer -> $subject."
      continue
    fi

    out_final="${KEYDIR}/${signer}-${subject}.cert"

    echo "Signing: signer='$signer'  ->  subject='${subject}'"

    set +e
    ssh-keygen -s "$signer_priv" -I "${signer}-${subject}" -n "testuser" $VALIDITY -z $((zserial++)) "$subject_pub"
    rc=$?
    set -e

    # rename so it fits our pattern
    if [ -f "$KEYDIR/${subject}-cert.pub" ]; then
      mv "$KEYDIR/${subject}-cert.pub" "$out_final"
      echo "OK -> $out_final"
    else
      echo "WARN: Did not find ${subject}-cert.pub. Skipping."
    fi

  done
done
