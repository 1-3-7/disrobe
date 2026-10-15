package main

import (
	"fmt"
	"reflect"
)

type Parcel struct {
	Destination string
	Priority    uint16
}

type Ledger struct {
	Owner   string
	Entries [1]Parcel
}

type Courier interface {
	Deliver(Parcel) string
}

func (ledger Ledger) Summary() string {
	return fmt.Sprintf("%s:%d", ledger.Owner, len(ledger.Entries))
}

func (ledger *Ledger) Add(parcel Parcel) {
	ledger.Entries[0] = parcel
}

func (ledger Ledger) Deliver(parcel Parcel) string {
	return ledger.Owner + ":" + parcel.Destination
}

func ParcelDestination(parcel Parcel) string {
	return parcel.Destination
}

func ParcelPriority(parcel Parcel) uint16 {
	return parcel.Priority
}

func LedgerOwner(ledger Ledger) string {
	return ledger.Owner
}

func LedgerEntries(ledger Ledger) [1]Parcel {
	return ledger.Entries
}

func TypeParcelEqual(left Parcel, right Parcel) bool {
	return left == right
}

func TypeLedgerEqual(left Ledger, right Ledger) bool {
	return left == right
}

func main() {
	ledger := Ledger{Owner: "dispatch"}
	ledger.Add(Parcel{Destination: "north", Priority: 7})
	var courier Courier = ledger
	fmt.Println(
		courier.Deliver(ledger.Entries[0]),
		ledger.Summary(),
		reflect.TypeOf(ledger).Name(),
		ParcelDestination(ledger.Entries[0]),
		ParcelPriority(ledger.Entries[0]),
		LedgerOwner(ledger),
		len(LedgerEntries(ledger)),
		TypeParcelEqual(Parcel{}, Parcel{}),
		TypeLedgerEqual(Ledger{}, Ledger{}),
	)
}
