// Copyright 2023 The Go SSI Framework Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package diddoc

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
)

var (
	errUnsupportedSourceType      error = errors.New("unspported_source_type")
	errUnsupportedDestinationType error = errors.New("unspported_destination_type")
	errUnadressable               error = errors.New("unadressable_interface")
	errNotAPointer                error = errors.New("invalid_interface")
	errStructNotEqual             error = errors.New("unsupported_struct")
	errMapNotEqual                error = errors.New("unsupported_map")
)

func encode(d interface{}, s interface{}) error {
	dv := reflect.ValueOf(d)
	if dv.Kind() != reflect.Pointer || dv.IsNil() {
		panic(errNotAPointer)
	}
	dv = dv.Elem()

	if !dv.CanAddr() {
		return errUnadressable
	}
	sv := reflect.ValueOf(s)
	dt := reflect.TypeOf(d).Elem()
	if sv.IsValid() {
		if err := valueEncoder(dv, dt, sv); err != nil {
			return err
		}
	}
	return nil
}

func valueEncoder(dv reflect.Value, dt reflect.Type, sv reflect.Value) error {
	switch dt.Kind() {

	case reflect.String:
		if err := stringEncoder(dv, sv); err != nil {
			return err
		}
		return nil

	case reflect.Interface:
		if err := interfaceEncoder(dv, sv); err != nil {
			return err
		}
		return nil

	case reflect.Struct:
		if err := structEncoder(dv, dt, sv); err != nil {
			return err
		}
		return nil

	case reflect.Map:
		if err := mapEncoder(dv, dt, sv); err != nil {
			return err
		}
		return nil

	case reflect.Slice, reflect.Array:
		if err := arrayEncoder(dv, dt, sv); err != nil {
			return err
		}
		return nil

	default:
		return errUnsupportedDestinationType
	}
}

// floatEncoder encodes the source value to a string value
func stringEncoder(dv reflect.Value, sv reflect.Value) error {
	switch sv.Kind() {
	case reflect.Bool:
		dv.SetString(strconv.FormatBool(sv.Bool()))
	case reflect.String:
		dv.SetString(sv.String())
	case reflect.Slice:
		// only allow a bytes slice
		if sv.Type().Elem().Kind() == reflect.Uint8 {
			dv.SetString(string(sv.Bytes()))
		} else {
			return errUnsupportedSourceType
		}
	case reflect.Interface, reflect.Pointer:
		if sv.IsValid() {
			if err := stringEncoder(dv, sv.Elem()); err != nil {
				return err
			}
		}
	default:
		return errUnsupportedSourceType
	}
	return nil
}

// interfaceEncoder encodes the source value to an interface
func interfaceEncoder(dv reflect.Value, sv reflect.Value) error {
	switch sv.Kind() {
	case reflect.Interface, reflect.Pointer:
		if sv.IsValid() {
			return interfaceEncoder(dv, sv.Elem())
		}
	default:
		dv.Set(sv)
	}
	return nil
}

// arrayEncoder encodes the source value to an array or slice
func arrayEncoder(dv reflect.Value, dt reflect.Type, sv reflect.Value) error {
	switch sv.Kind() {
	case reflect.Array, reflect.Slice:
		if dt.Elem().Kind() == reflect.String && sv.Type().Elem().Kind() == reflect.Uint8 {
			xv := reflect.New(dt.Elem()).Elem()
			valueEncoder(xv, dt.Elem(), sv)
			dv.Set(reflect.Append(dv, xv))
		} else {
			for i := 0; i < sv.Len(); i++ {
				xv := reflect.New(dt.Elem()).Elem()

				valueEncoder(xv, xv.Type(), sv.Index(i))
				dv.Set(reflect.Append(dv, xv))
			}
		}
	case reflect.Interface:
		valueEncoder(dv, dt, sv.Elem())
	default:
		xv := reflect.New(dt.Elem()).Elem()
		valueEncoder(xv, dt.Elem(), sv)
		dv.Set(reflect.Append(dv, xv))
	}
	return nil
}

// mapEncoder encodes the source value to a map
func mapEncoder(dv reflect.Value, dt reflect.Type, sv reflect.Value) error {
	switch sv.Kind() {
	case reflect.Map:
		if dt != sv.Type() {
			return errMapNotEqual
		}
		dv.Set(sv)
	default:
		return errUnsupportedSourceType
	}
	return nil
}

// structEncoder encodes the source value to a struct
func structEncoder(dv reflect.Value, dt reflect.Type, sv reflect.Value) error {
	switch sv.Kind() {
	case reflect.Interface:
		if sv.IsValid() {
			if err := structEncoder(dv, dt, sv.Elem()); err != nil {
				return err
			}
		}
	case reflect.Struct:
		// types must be the same to assign the value
		if dt != sv.Type() {
			return errStructNotEqual
		}
		dv.Set(sv)
	case reflect.Map:
		xv := reflect.New(dt).Elem()
		for i := 0; i < dt.NumField(); i++ {
			key := strings.Split(dt.Field(i).Tag.Get("json"), ",")
			sourceValue := sv.MapIndex(reflect.ValueOf(key[0]))

			if sourceValue.IsValid() && sourceValue.CanInterface() {
				if err := valueEncoder(xv.Field(i), dt.Field(i).Type, sourceValue); err != nil {
					return err
				}
			}
		}
		dv.Set(xv)
	default:
		return errUnsupportedSourceType
	}
	return nil
}
