package storage

import (
	"io/ioutil"
	"testing"
)

func testStorage(s *Storage, t *testing.T) {
	var err error

	var wantint = 42
	var testint int
	if err = s.Set("int", wantint); err != nil {
		t.Error(err)
		return
	}
	if !s.Has("int") {
		t.Error("key int not found in s.Has")
		return
	}
	if err = s.Get("int", &testint); err != nil {
		t.Error("key int not found in s.Get: " + err.Error())
		return
	}
	if testint != wantint {
		t.Error("value int corrupted")
		return
	}

	var wantstr = "testing"
	var teststr string
	if err = s.Set("str", wantstr); err != nil {
		t.Error(err)
		return
	}
	if !s.Has("str") {
		t.Error("key str not found in s.Has")
		return
	}
	if err = s.Get("str", &teststr); err != nil {
		t.Error("key str not found in s.Get: " + err.Error())
		return
	}
	if teststr != wantstr {
		t.Error("value str corrupted")
		return
	}

	var wantmap = map[string]int{"foo": 42, "bar": 23}
	var testmap map[string]int
	s.Set("map", wantmap)
	if !s.Has("map") {
		t.Error("key map not found in s.Has")
		return
	}
	if err = s.Get("map", &testmap); err != nil {
		t.Error("key map not found in s.Get: " + err.Error())
		return
	}
	if testmap["foo"] != wantmap["foo"] || testmap["bar"] != wantmap["bar"] {
		t.Error("value map corrupted")
		return
	}

	var want = "hello.world"
	var test string
	if err = s.Set("hello.world", want); err != nil {
		t.Error(err)
		return
	}
	if !s.Has("hello.world") {
		t.Error("key hello.world not found in s.Has")
		return
	}
	if err = s.Get("hello.world", &test); err != nil {
		t.Error("key hello.world not found in s.Get: " + err.Error())
		return
	}
	if test != want {
		t.Error("value hello.world corrupted")
	}

	/*
		for key := range s.Scan("") {
			if err = s.Delete(key); err != nil {
				t.Error("key %s delete failed: " + err.Error())
				continue
			}
		}
	*/
}

func TestJSON(t *testing.T) {
	temp, err := ioutil.TempDir("", "storage-json")
	if err != nil {
		t.Error(err)
		return
	}
	t.Log(temp)
	//defer os.RemoveAll(temp)

	var b Backend

	o := NewOptions(temp)
	b, err = NewJSONBackend(o)
	if err != nil {
		t.Error(err)
		return
	}

	s := New(b)
	testStorage(s, t)

	o.Extra["compress"] = true
	b, err = NewJSONBackend(o)
	if err != nil {
		t.Error(err)
		return
	}
	c := New(b)
	testStorage(c, t)

	// Cleanup, but only if our tests were successful
	//os.RemoveAll(temp)
}
