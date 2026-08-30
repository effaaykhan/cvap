package protocol_test

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"

	scanpointv1 "github.com/effaaykhan/cvap/gen/cybersentinel/scanpoint/v1"
)

const wirePackage = "cybersentinel.scanpoint.v1"

// How many extra fields a "future" version adds to each message, and the wire
// types they exercise. Between them they cover all four proto3 wire types, so a
// parser that mishandles one length-delimited field but not a varint has
// nowhere to hide.
var futureFieldTypes = []struct {
	suffix   string
	typ      descriptorpb.FieldDescriptorProto_Type
	repeated bool
}{
	{"future_note", descriptorpb.FieldDescriptorProto_TYPE_STRING, false},  // wire type 2
	{"future_tags", descriptorpb.FieldDescriptorProto_TYPE_STRING, true},   // wire type 2, repeated
	{"future_count", descriptorpb.FieldDescriptorProto_TYPE_INT64, false},  // wire type 0
	{"future_ratio", descriptorpb.FieldDescriptorProto_TYPE_DOUBLE, false}, // wire type 1
	{"future_weight", descriptorpb.FieldDescriptorProto_TYPE_FLOAT, false}, // wire type 5
	{"future_blob", descriptorpb.FieldDescriptorProto_TYPE_BYTES, false},   // wire type 2, bytes
}

// ---------------------------------------------------------------------------
// Building a future version of the contract
// ---------------------------------------------------------------------------

// currentFileDescriptorProtos returns the contract as it is compiled into this
// binary today.
func currentFileDescriptorProtos(t *testing.T) []*descriptorpb.FileDescriptorProto {
	t.Helper()

	var out []*descriptorpb.FileDescriptorProto
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		if string(fd.Package()) == wirePackage {
			out = append(out, protodesc.ToFileDescriptorProto(fd))
		}
		return true
	})
	sort.Slice(out, func(i, j int) bool { return out[i].GetName() < out[j].GetName() })

	if len(out) == 0 {
		t.Fatalf("no files registered for package %s -- the generated bindings are not linked in", wirePackage)
	}
	return out
}

// futureRegistry builds a descriptor set representing a later version of the
// contract, in its own registry so it never collides with the real one.
//
// This is the whole trick of the file: it lets us construct messages that a
// future Core would send without there being any such .proto on disk, and
// therefore without the test drifting out of date the moment someone adds a
// field.
func futureRegistry(t *testing.T, mutate func(*descriptorpb.DescriptorProto)) *protoregistry.Files {
	t.Helper()

	set := &descriptorpb.FileDescriptorSet{File: currentFileDescriptorProtos(t)}
	for _, file := range set.File {
		for _, message := range file.MessageType {
			mutate(message)
		}
	}

	files, err := protodesc.NewFiles(set)
	if err != nil {
		t.Fatalf("building the future descriptor set: %v", err)
	}
	return files
}

// addFutureFields appends fields at the numbers a later version would use --
// the first free ones after everything the message defines today.
func addFutureFields(message *descriptorpb.DescriptorProto) {
	next := int32(0)
	for _, f := range message.Field {
		if f.GetNumber() > next {
			next = f.GetNumber()
		}
	}

	for _, spec := range futureFieldTypes {
		next++
		label := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL
		if spec.repeated {
			label = descriptorpb.FieldDescriptorProto_LABEL_REPEATED
		}
		message.Field = append(message.Field, &descriptorpb.FieldDescriptorProto{
			Name:     proto.String(spec.suffix),
			JsonName: proto.String(jsonName(spec.suffix)),
			Number:   proto.Int32(next),
			Label:    label.Enum(),
			Type:     spec.typ.Enum(),
		})
	}
}

func jsonName(snake string) string {
	parts := strings.Split(snake, "_")
	for i := 1; i < len(parts); i++ {
		parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
	}
	return strings.Join(parts, "")
}

// ---------------------------------------------------------------------------
// Populating a message generically
// ---------------------------------------------------------------------------

// populate fills every field with a recognisable, non-zero value.
//
// Non-zero matters: proto3 does not put a zero-valued scalar on the wire, so a
// message populated with defaults would serialise to nothing and every
// assertion below would pass vacuously.
func populate(m protoreflect.Message, depth int) {
	if depth > 4 {
		return
	}

	seenOneof := map[protoreflect.FullName]bool{}
	fields := m.Descriptor().Fields()

	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)

		// Exactly one arm of each oneof, which is all the wire can carry.
		if od := fd.ContainingOneof(); od != nil {
			if seenOneof[od.FullName()] {
				continue
			}
			seenOneof[od.FullName()] = true
		}

		switch {
		case fd.IsMap():
			// The contract has no maps. If one is added, it needs its own case
			// rather than being silently skipped.
			continue

		case fd.IsList():
			list := m.Mutable(fd).List()
			for n := 0; n < 2; n++ {
				if fd.Kind() == protoreflect.MessageKind || fd.Kind() == protoreflect.GroupKind {
					elem := list.NewElement()
					populate(elem.Message(), depth+1)
					list.Append(elem)
					continue
				}
				list.Append(scalarValue(fd, int64(fd.Number())*100+int64(n)))
			}

		case fd.Kind() == protoreflect.MessageKind, fd.Kind() == protoreflect.GroupKind:
			populate(m.Mutable(fd).Message(), depth+1)

		default:
			m.Set(fd, scalarValue(fd, int64(fd.Number())))
		}
	}
}

func scalarValue(fd protoreflect.FieldDescriptor, seed int64) protoreflect.Value {
	switch fd.Kind() {
	case protoreflect.BoolKind:
		return protoreflect.ValueOfBool(true)
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return protoreflect.ValueOfInt32(int32(seed))
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return protoreflect.ValueOfInt64(seed)
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return protoreflect.ValueOfUint32(uint32(seed))
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return protoreflect.ValueOfUint64(uint64(seed))
	case protoreflect.FloatKind:
		return protoreflect.ValueOfFloat32(float32(seed) + 0.5)
	case protoreflect.DoubleKind:
		return protoreflect.ValueOfFloat64(float64(seed) + 0.25)
	case protoreflect.StringKind:
		return protoreflect.ValueOfString(fmt.Sprintf("v-%d", seed))
	case protoreflect.BytesKind:
		return protoreflect.ValueOfBytes([]byte(fmt.Sprintf("b-%d", seed)))
	case protoreflect.EnumKind:
		values := fd.Enum().Values()
		idx := 0
		if values.Len() > 1 {
			idx = 1 // never the UNSPECIFIED zero, which would not be serialised
		}
		return protoreflect.ValueOfEnum(values.Get(idx).Number())
	}
	panic(fmt.Sprintf("no value builder for kind %v on field %s", fd.Kind(), fd.FullName()))
}

// ---------------------------------------------------------------------------
// The test ADR-022 requires
// ---------------------------------------------------------------------------

// TestFutureFieldsRoundTripThroughCurrentTypes is the test that proves an old
// scan point still works.
//
// For every message in the contract it builds the message as a future version
// would send it -- extra fields at every level of nesting -- serialises it,
// parses it with the types this build actually has, and asserts three things:
//
//  1. the future fields really were unknown, so the case is testing something;
//  2. every field this build does know survived the parse intact;
//  3. re-serialising and re-parsing recovers the future fields byte-for-byte.
//
// The third is the one that matters most and the one that is easy to omit. It
// is the difference between "an old build tolerates new fields" and "an old
// build does not destroy them". Under ADR-026 a scan point that cannot reach
// Core buffers results locally for up to 24 hours and resubmits them, so a
// message can be parsed and re-serialised by a months-old build before Core
// ever sees it. If unknown fields are dropped on that hop, the data is lost
// inside a customer network, silently, and the eventual symptom -- findings
// that were never generated -- points nowhere near the cause.
func TestFutureFieldsRoundTripThroughCurrentTypes(t *testing.T) {
	future := futureRegistry(t, addFutureFields)

	for _, name := range messageNames(t) {
		t.Run(string(name), func(t *testing.T) {
			futureDesc := lookupMessage(t, future, name)

			currentType, err := protoregistry.GlobalTypes.FindMessageByName(name)
			if err != nil {
				t.Fatalf("no generated type for %s: %v", name, err)
			}
			currentDesc := currentType.Descriptor()

			sent := dynamicpb.NewMessage(futureDesc)
			populate(sent, 0)

			sentBytes, err := proto.Marshal(sent.Interface())
			if err != nil {
				t.Fatalf("marshalling the future message: %v", err)
			}

			received := currentType.New().Interface()
			if err := proto.Unmarshal(sentBytes, received); err != nil {
				t.Fatalf("current build could not parse a future %s at all: %v", name, err)
			}

			// (1) The future fields were genuinely unknown to this build.
			// Without this the other two assertions could pass while comparing
			// a message to itself.
			if len(received.ProtoReflect().GetUnknown()) == 0 {
				t.Fatalf("%s: no unknown fields after parsing a future message -- "+
					"the future descriptor is not actually ahead of the current one, "+
					"so this case proves nothing", name)
			}

			// (2) Known fields survived.
			knownOnly := proto.Clone(sent.Interface()).ProtoReflect()
			for _, fd := range extraFields(futureDesc, currentDesc) {
				knownOnly.Clear(fd)
			}
			knownBytes, err := proto.Marshal(knownOnly.Interface())
			if err != nil {
				t.Fatalf("marshalling the known-fields-only message: %v", err)
			}
			expected := currentType.New().Interface()
			if err := proto.Unmarshal(knownBytes, expected); err != nil {
				t.Fatalf("parsing the known-fields-only message: %v", err)
			}

			actual := proto.Clone(received)
			actual.ProtoReflect().SetUnknown(nil)

			if !proto.Equal(expected, actual) {
				t.Errorf("%s: known fields did not survive a parse alongside unknown ones\n"+
					" want: %v\n  got: %v", name, expected, actual)
			}

			// (3) The round trip preserves what this build cannot read. This is
			// the buffer-and-resubmit path in ADR-026.
			relayed, err := proto.Marshal(received)
			if err != nil {
				t.Fatalf("re-marshalling after parse: %v", err)
			}
			recovered := dynamicpb.NewMessage(futureDesc)
			if err := proto.Unmarshal(relayed, recovered.Interface()); err != nil {
				t.Fatalf("future build could not re-parse a relayed %s: %v", name, err)
			}

			if !proto.Equal(sent.Interface(), recovered.Interface()) {
				t.Errorf("%s: fields were destroyed by a round trip through the current build.\n"+
					"An old scan point buffering and resubmitting this message (ADR-026) "+
					"would silently lose data.\n sent: %v\n back: %v",
					name, sent.Interface(), recovered.Interface())
			}
		})
	}
}

// TestUnknownOneofArmIsTolerated covers the case a plain added field does not:
// a future Core sending a CoreMessage variant this build has no arm for.
//
// A scan point that errors, or panics on a nil oneof, is the fleet-wide outage
// in networks we cannot reach that ADR-022 exists to prevent -- and it would
// look like every scan point in the estate going quiet at once, shortly after a
// Core deploy.
func TestUnknownOneofArmIsTolerated(t *testing.T) {
	const target = "CoreMessage"

	future := futureRegistry(t, func(message *descriptorpb.DescriptorProto) {
		if message.GetName() != target {
			return
		}
		next := int32(0)
		for _, f := range message.Field {
			if f.GetNumber() > next {
				next = f.GetNumber()
			}
		}
		message.Field = append(message.Field, &descriptorpb.FieldDescriptorProto{
			Name:       proto.String("future_directive"),
			JsonName:   proto.String("futureDirective"),
			Number:     proto.Int32(next + 1),
			Label:      descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
			Type:       descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(),
			TypeName:   proto.String("." + wirePackage + ".Capability"),
			OneofIndex: proto.Int32(0),
		})
	})

	futureDesc := lookupMessage(t, future, wirePackage+"."+target)
	armDesc := futureDesc.Fields().ByName("future_directive")
	if armDesc == nil {
		t.Fatal("future_directive was not added to the oneof")
	}

	sent := dynamicpb.NewMessage(futureDesc)
	arm := sent.NewField(armDesc)
	populate(arm.Message(), 0)
	sent.Set(armDesc, arm)

	sentBytes, err := proto.Marshal(sent.Interface())
	if err != nil {
		t.Fatalf("marshalling the future CoreMessage: %v", err)
	}

	var received scanpointv1.CoreMessage
	if err := proto.Unmarshal(sentBytes, &received); err != nil {
		t.Fatalf("current build rejected a CoreMessage carrying an unknown oneof arm: %v", err)
	}

	if received.GetMsg() != nil {
		t.Errorf("expected no recognised oneof arm, got %T", received.GetMsg())
	}
	if len(received.ProtoReflect().GetUnknown()) == 0 {
		t.Fatal("the unknown arm was not retained as an unknown field")
	}

	relayed, err := proto.Marshal(&received)
	if err != nil {
		t.Fatalf("re-marshalling: %v", err)
	}
	recovered := dynamicpb.NewMessage(futureDesc)
	if err := proto.Unmarshal(relayed, recovered.Interface()); err != nil {
		t.Fatalf("re-parsing the relayed message: %v", err)
	}
	if !proto.Equal(sent.Interface(), recovered.Interface()) {
		t.Errorf("the unknown oneof arm did not survive a round trip\n sent: %v\n back: %v",
			sent.Interface(), recovered.Interface())
	}
}

// TestUnknownEnumValueSurvives covers the other half of forward compatibility,
// which no amount of unknown-field handling addresses.
//
// SubmitStatus is the vocabulary most likely to grow: ADR-026 chose five
// outcomes because two were not enough to tell a scan point what to do with its
// buffer, and a sixth is a plausible additive change. proto3 enums are open, so
// the number survives -- but only if nothing in the parse path coerces an
// unrecognised value to the zero one on the way through.
func TestUnknownEnumValueSurvives(t *testing.T) {
	const futureStatus = 6 // one past RETRY_LATER

	if v := scanpointv1.SubmitStatus(0).Descriptor().Values().ByNumber(futureStatus); v != nil {
		t.Fatalf("SubmitStatus %d is now defined as %s -- raise the constant in this test "+
			"to the next free number so it keeps testing an unknown value", futureStatus, v.Name())
	}

	sent := &scanpointv1.SubmitAck{
		SubmissionId:      "sub-1",
		LastChunkAccepted: 3,
		Status:            scanpointv1.SubmitStatus(futureStatus),
		RetryAfterMs:      250,
		Detail:            "a status this build has never heard of",
	}

	sentBytes, err := proto.Marshal(sent)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}

	var received scanpointv1.SubmitAck
	if err := proto.Unmarshal(sentBytes, &received); err != nil {
		t.Fatalf("parsing an ack with an unknown status: %v", err)
	}

	if int32(received.GetStatus()) != futureStatus {
		t.Errorf("unknown enum value was not preserved: want %d, got %d (%s)",
			futureStatus, received.GetStatus(), received.GetStatus())
	}
	if !proto.Equal(sent, &received) {
		t.Errorf("ack did not round trip\n sent: %v\n back: %v", sent, &received)
	}
}

// ---------------------------------------------------------------------------
// Constraints that are stated in execution-plan 4.2 and otherwise unenforced
// ---------------------------------------------------------------------------

// TestEveryEnumHasUnspecifiedZero holds the line on the zero value.
//
// Under ADR-022 an enum's zero value is permanent, and proto3 does not put a
// zero-valued field on the wire. An enum whose zero is a real state therefore
// makes "the sender meant this" and "the sender is an older build that never
// set the field" the same bytes, which is unrecoverable after the fact.
func TestEveryEnumHasUnspecifiedZero(t *testing.T) {
	for _, ed := range enumDescriptors(t) {
		zero := ed.Values().ByNumber(0)
		if zero == nil {
			t.Errorf("%s has no zero value", ed.FullName())
			continue
		}
		if !strings.HasSuffix(string(zero.Name()), "_UNSPECIFIED") {
			t.Errorf("%s zero value is %s, want a name ending _UNSPECIFIED", ed.FullName(), zero.Name())
		}
	}
}

// TestHotPathFieldsUseSingleByteTags guards the reservation of 1-15.
//
// Field numbers 1-15 encode their tag in one byte; 16 and above take two. At
// the 5,000 observations/sec ingest target these three messages dominate the
// wire, and the numbering cannot be revisited later -- renumbering is exactly
// what ADR-022 forbids. This is the only moment the choice is available.
func TestHotPathFieldsUseSingleByteTags(t *testing.T) {
	hotPath := []string{"Observation", "ResultChunk", "RulePackChunk"}

	for _, name := range hotPath {
		md, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(wirePackage + "." + name))
		if err != nil {
			t.Fatalf("%s not found: %v", name, err)
		}
		fields := md.(protoreflect.MessageDescriptor).Fields()
		for i := 0; i < fields.Len(); i++ {
			if n := fields.Get(i).Number(); n > 15 {
				t.Errorf("%s.%s is field %d; the hot path is reserved to 1-15 for single-byte tags",
					name, fields.Get(i).Name(), n)
			}
		}
	}
}

// TestServiceShapeIsFrozen pins the four services and their streaming
// cardinality.
//
// ADR-026 records that changing an RPC's streaming shape is a major-version
// break rather than an additive change -- it is why SubmitResults is
// bidirectional rather than taking a single terminal ack, since a terminal-only
// ack can express neither a resumption point nor backpressure while the upload
// is still running. `buf breaking` reports a cardinality change as a change to
// a service rather than to a field, which is the kind of line that gets waved
// through in review.
func TestServiceShapeIsFrozen(t *testing.T) {
	want := map[string]map[string]shape{
		"Enrollment": {
			"Enroll":            {false, false},
			"RotateCertificate": {false, false},
		},
		"Dispatch": {
			"Connect": {true, true},
		},
		"Ingest": {
			"SubmitResults": {true, true},
		},
		"RulePacks": {
			"FetchRulePack": {false, true},
		},
	}

	got := map[string]map[string]shape{}
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		if string(fd.Package()) != wirePackage {
			return true
		}
		services := fd.Services()
		for i := 0; i < services.Len(); i++ {
			sd := services.Get(i)
			methods := map[string]shape{}
			for j := 0; j < sd.Methods().Len(); j++ {
				md := sd.Methods().Get(j)
				methods[string(md.Name())] = shape{md.IsStreamingClient(), md.IsStreamingServer()}
			}
			got[string(sd.Name())] = methods
		}
		return true
	})

	if len(got) != len(want) {
		t.Errorf("service count changed: want %d services, got %d %v", len(want), len(got), serviceNames(got))
	}
	for service, methods := range want {
		gotMethods, ok := got[service]
		if !ok {
			t.Errorf("service %s is missing", service)
			continue
		}
		for method, wantShape := range methods {
			gotShape, ok := gotMethods[method]
			if !ok {
				t.Errorf("%s.%s is missing", service, method)
				continue
			}
			if gotShape != wantShape {
				t.Errorf("%s.%s streaming cardinality changed: want client=%v server=%v, got client=%v server=%v "+
					"-- this is a major-version break under ADR-022, not an additive change",
					service, method, wantShape.clientStream, wantShape.serverStream,
					gotShape.clientStream, gotShape.serverStream)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func messageNames(t *testing.T) []protoreflect.FullName {
	t.Helper()

	var names []protoreflect.FullName
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		if string(fd.Package()) != wirePackage {
			return true
		}
		messages := fd.Messages()
		for i := 0; i < messages.Len(); i++ {
			names = append(names, messages.Get(i).FullName())
		}
		return true
	})
	sort.Slice(names, func(i, j int) bool { return names[i] < names[j] })

	if len(names) == 0 {
		t.Fatalf("no messages found in %s", wirePackage)
	}
	return names
}

func enumDescriptors(t *testing.T) []protoreflect.EnumDescriptor {
	t.Helper()

	var enums []protoreflect.EnumDescriptor
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		if string(fd.Package()) != wirePackage {
			return true
		}
		for i := 0; i < fd.Enums().Len(); i++ {
			enums = append(enums, fd.Enums().Get(i))
		}
		messages := fd.Messages()
		for i := 0; i < messages.Len(); i++ {
			nested := messages.Get(i).Enums()
			for j := 0; j < nested.Len(); j++ {
				enums = append(enums, nested.Get(j))
			}
		}
		return true
	})

	if len(enums) == 0 {
		t.Fatalf("no enums found in %s", wirePackage)
	}
	return enums
}

func lookupMessage(t *testing.T, files *protoregistry.Files, name protoreflect.FullName) protoreflect.MessageDescriptor {
	t.Helper()

	d, err := files.FindDescriptorByName(name)
	if err != nil {
		t.Fatalf("looking up %s in the future registry: %v", name, err)
	}
	md, ok := d.(protoreflect.MessageDescriptor)
	if !ok {
		t.Fatalf("%s is not a message", name)
	}
	return md
}

// extraFields returns the fields the future descriptor has and the current one
// does not.
func extraFields(future, current protoreflect.MessageDescriptor) []protoreflect.FieldDescriptor {
	var extra []protoreflect.FieldDescriptor
	fields := future.Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		if current.Fields().ByNumber(fd.Number()) == nil {
			extra = append(extra, fd)
		}
	}
	return extra
}

// shape is an RPC's streaming cardinality: whether the client streams, and
// whether the server does.
type shape struct{ clientStream, serverStream bool }

func serviceNames(m map[string]map[string]shape) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
