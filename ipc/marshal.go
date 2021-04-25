//
// marshal.go
//
// Copyright (c) 2018-2021 Markku Rossi
//
// All rights reserved.
//

package ipc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
)

// Marshal encodes the value into IPC encoding.
func Marshal(v interface{}) ([]byte, error) {
	out := new(bytes.Buffer)

	err := marshalValue(out, reflect.ValueOf(v))
	if err != nil {
		return nil, err
	}

	return out.Bytes(), nil
}

func marshalValue(out io.Writer, value reflect.Value) error {
	var buf [8]byte

	if !value.IsValid() {
		return nil
	}

	switch value.Type().Kind() {

	case reflect.Bool:
		if value.Bool() {
			buf[0] = 1
		} else {
			buf[0] = 0
		}
		_, err := out.Write(buf[:1])
		return err

	case reflect.Uint8:
		buf[0] = uint8(value.Uint())
		_, err := out.Write(buf[:1])
		return err

	case reflect.Int:
		binary.BigEndian.PutUint32(buf[:4], uint32(value.Int()))
		_, err := out.Write(buf[:4])
		return err

	case reflect.Uint32:
		binary.BigEndian.PutUint32(buf[:4], uint32(value.Uint()))
		_, err := out.Write(buf[:4])
		return err

	case reflect.Uint64:
		binary.BigEndian.PutUint64(buf[:8], value.Uint())
		_, err := out.Write(buf[:8])
		return err

	case reflect.Int64:
		binary.BigEndian.PutUint64(buf[:8], uint64(value.Int()))
		_, err := out.Write(buf[:8])
		return err

	case reflect.Slice:
		binary.BigEndian.PutUint32(buf[:4], uint32(value.Len()))
		_, err := out.Write(buf[:4])
		if err != nil {
			return err
		}
		if value.Type().Elem().Kind() == reflect.Uint8 {
			_, err = out.Write(value.Bytes())
			return err
		}
		for i := 0; i < value.Len(); i++ {
			if err := marshalValue(out, value.Index(i)); err != nil {
				return err
			}
		}
		return nil

	case reflect.Array:
		binary.BigEndian.PutUint32(buf[:4], uint32(value.Len()))
		_, err := out.Write(buf[:4])
		if err != nil {
			return err
		}
		for i := 0; i < value.Len(); i++ {
			if err := marshalValue(out, value.Index(i)); err != nil {
				return err
			}
		}
		return nil

	case reflect.String:
		data := []byte(value.String())
		binary.BigEndian.PutUint32(buf[:4], uint32(len(data)))
		_, err := out.Write(buf[:4])
		if err != nil {
			return err
		}
		_, err = out.Write(data)
		return err

	case reflect.Ptr:
		return marshalValue(out, reflect.Indirect(value))

	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			err := marshalValue(out, value.Field(i))
			if err != nil {
				return err
			}
		}

	default:
		return fmt.Errorf("marshal: unsupported type: %s", value.Type().Kind())
	}

	return nil
}

// Unmarshal decodes the value from the IPC encoding.
func Unmarshal(data []byte, v interface{}) error {
	return unmarshalValue(bytes.NewReader(data), reflect.ValueOf(v))
}

func unmarshalValue(in io.Reader, value reflect.Value) (err error) {
	var buf [8]byte

	if !value.IsValid() {
		return nil
	}

	switch value.Type().Kind() {
	case reflect.Bool:
		_, err = io.ReadFull(in, buf[:1])
		if err != nil {
			return
		}
		if buf[0] == 0 {
			value.SetBool(false)
		} else {
			value.SetBool(true)
		}

	case reflect.Uint8:
		_, err = io.ReadFull(in, buf[:1])
		if err != nil {
			return
		}
		value.SetUint(uint64(buf[0]))

	case reflect.Int:
		_, err = io.ReadFull(in, buf[:4])
		if err != nil {
			return
		}
		value.SetInt(int64(binary.BigEndian.Uint32(buf[:4])))

	case reflect.Uint32:
		_, err = io.ReadFull(in, buf[:4])
		if err != nil {
			return
		}
		value.SetUint(uint64(binary.BigEndian.Uint32(buf[:4])))

	case reflect.Int64:
		_, err = io.ReadFull(in, buf[:8])
		if err != nil {
			return
		}
		value.SetInt(int64(binary.BigEndian.Uint64(buf[:8])))

	case reflect.Slice:
		_, err := io.ReadFull(in, buf[:4])
		if err != nil {
			return err
		}
		count := binary.BigEndian.Uint32(buf[:4])
		if value.Type().Elem().Kind() == reflect.Uint8 {
			data := make([]byte, count)
			_, err := io.ReadFull(in, data)
			if err != nil {
				return err
			}
			value.SetBytes(data)
		} else {
			slice := reflect.MakeSlice(value.Type(), int(count), int(count))
			for i := 0; uint32(i) < count; i++ {
				el := reflect.New(value.Type().Elem())
				if err := unmarshalValue(in, el); err != nil {
					return err
				}
				slice.Index(i).Set(reflect.Indirect(el))
			}
			value.Set(slice)
		}

	case reflect.Array:
		_, err := io.ReadFull(in, buf[:4])
		if err != nil {
			return err
		}
		count := binary.BigEndian.Uint32(buf[:4])
		array := reflect.New(value.Type())
		for i := 0; uint32(i) < count; i++ {
			el := reflect.New(value.Type().Elem())
			if err := unmarshalValue(in, el); err != nil {
				return err
			}
			array.Index(i).Set(reflect.Indirect(el))
		}
		value.Set(array)

	case reflect.String:
		_, err := io.ReadFull(in, buf[:4])
		if err != nil {
			return err
		}
		count := binary.BigEndian.Uint32(buf[:4])
		data := make([]byte, count)
		_, err = io.ReadFull(in, data)
		if err != nil {
			return err
		}
		value.SetString(string(data))

	case reflect.Ptr:
		pointed := reflect.Indirect(value)
		if !pointed.IsValid() {
			pointed = reflect.New(value.Type().Elem())
			value.Set(pointed)
		}
		return unmarshalValue(in, pointed)

	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			err = unmarshalValue(in, value.Field(i))
			if err != nil {
				return
			}
		}

	default:
		return fmt.Errorf("ummarshal: unsupported type: %s",
			value.Type().Kind())
	}

	return
}
