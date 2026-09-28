package config

import (
	"encoding/json"
	"fmt"
)

// ApplyMergePatch applies an RFC 7386 JSON merge patch to a document.
//
// Implemented here rather than pulled in as a dependency: the algorithm is ten lines
// and fully specified, and the panel needs to be sure about one specific behaviour —
// that a null value deletes a key. That is how an operator removes something the
// generator emits, and a library that treated null as "set to null" would silently
// produce a config Xray rejects.
//
// Note that merge patch replaces arrays wholesale; there is no element-wise merge.
// An operator overriding `outbounds` supplies the entire list.
func ApplyMergePatch(target, patch []byte) ([]byte, error) {
	if len(patch) == 0 {
		return target, nil
	}

	var patchValue any
	if err := json.Unmarshal(patch, &patchValue); err != nil {
		return nil, fmt.Errorf("xray/config: patch is not valid JSON: %w", err)
	}

	// An empty object is a no-op patch, which is the stored default. Skipping the
	// round trip keeps the generated output byte-identical to the unpatched one.
	if object, ok := patchValue.(map[string]any); ok && len(object) == 0 {
		return target, nil
	}

	var targetValue any
	if err := json.Unmarshal(target, &targetValue); err != nil {
		return nil, fmt.Errorf("xray/config: target is not valid JSON: %w", err)
	}

	merged := mergeValue(targetValue, patchValue)

	out, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("xray/config: encode merged config: %w", err)
	}
	return out, nil
}

// mergeValue is the recursive half of RFC 7386.
func mergeValue(target, patch any) any {
	patchObject, patchIsObject := patch.(map[string]any)
	if !patchIsObject {
		// A non-object patch replaces the target outright, arrays included.
		return patch
	}

	targetObject, targetIsObject := target.(map[string]any)
	if !targetIsObject {
		// Merging an object into a non-object starts from an empty one, per the spec.
		targetObject = map[string]any{}
	}

	for key, value := range patchObject {
		if value == nil {
			// The delete case. This is the whole reason for not guessing at a
			// library's semantics here.
			delete(targetObject, key)
			continue
		}
		targetObject[key] = mergeValue(targetObject[key], value)
	}
	return targetObject
}
