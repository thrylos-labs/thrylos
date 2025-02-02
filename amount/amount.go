package amount

import (
	"errors"
	"math"
	"strconv"
)

const (
	NanoTHRYLOS = 1e9
)

type Unit int

const (
	MegaTHR  Unit = 6
	KiloTHR  Unit = 3
	THR      Unit = 0
	MilliTHR Unit = -3
	MicroTHR Unit = -6
	NanoTHR  Unit = -9
)

func (u Unit) String() string {
	switch u {
	case MegaTHR:
		return "MTHR"
	case KiloTHR:
		return "kTHR"
	case THR:
		return "THR"
	case MilliTHR:
		return "mTHR"
	case MicroTHR:
		return "μTHR"
	case NanoTHR:
		return "nTHR"
	default:
		return "1e" + strconv.FormatInt(int64(u), 10) + " THR"
	}
}

// Amount represents the atomic unit in THRYLOS blockchain.
// Each unit equals to 1e-9 of a THRYLOS.
type Amount int64

func round(f float64) Amount {
	if f < 0 {
		return Amount(f - 0.5)
	}
	return Amount(f + 0.5)
}

func NewAmount(f float64) (Amount, error) {
	switch {
	case math.IsNaN(f),
		math.IsInf(f, 1),
		math.IsInf(f, -1):
		return 0, errors.New("invalid THRYLOS amount")
	}

	return round(f * float64(NanoTHRYLOS)), nil
}

func FromString(str string) (Amount, error) {
	f, err := strconv.ParseFloat(str, 64)
	if err != nil {
		return 0, err
	}
	return NewAmount(f)
}

func (a Amount) ToUnit(u Unit) float64 {
	return float64(a) / math.Pow10(int(u+9))
}

func (a Amount) ToTHRYLOS() float64 {
	return a.ToUnit(THR)
}

func (a Amount) ToNanoTHR() int64 {
	return int64(a)
}

func (a Amount) Format(u Unit) string {
	units := " " + u.String()
	formatted := strconv.FormatFloat(a.ToUnit(u), 'f', -int(u+9), 64)
	return formatted + units
}

// String is the equivalent of calling Format with AmountTHR.
func (a Amount) String() string {
	return a.Format(THR)
}

func (a Amount) MulF64(f float64) Amount {
	return round(float64(a) * f)
}
