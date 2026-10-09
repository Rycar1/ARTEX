package db

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTaskTemplateCRUDAndNormalizedUniqueness(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	suffix := time.Now().UnixNano()
	name := fmt.Sprintf("Template %d", suffix)
	created, err := d.CreateTaskTemplate(TaskTemplateInput{
		Name:        "  " + strings.ReplaceAll(name, " ", "   ") + "  ",
		Description: "  initial description  ",
		Goal:        "  initial goal  ",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.DeleteTaskTemplate(created.ID) })
	if created.Name != name || created.Description != "initial description" || created.Goal != "initial goal" {
		t.Fatalf("template was not normalized: %+v", created)
	}

	if _, err := d.CreateTaskTemplate(TaskTemplateInput{
		Name: strings.ToUpper(name), Description: "duplicate", Goal: "duplicate",
	}); !errors.Is(err, ErrTaskTemplateNameConflict) {
		t.Fatalf("duplicate create error = %v, want %v", err, ErrTaskTemplateNameConflict)
	}

	got, err := d.GetTaskTemplate(created.ID)
	if err != nil || got == nil || got.Name != name {
		t.Fatalf("GetTaskTemplate = %+v, %v", got, err)
	}
	listed, err := d.ListTaskTemplates()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, template := range listed {
		if template.ID == created.ID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("created template %d missing from list", created.ID)
	}

	updatedName := name + " updated"
	updated, err := d.UpdateTaskTemplate(created.ID, TaskTemplateInput{
		Name: updatedName, Description: "new description", Goal: "new goal",
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != updatedName || updated.Description != "new description" || updated.Goal != "new goal" {
		t.Fatalf("unexpected updated template: %+v", updated)
	}

	if _, err := d.CreateTaskTemplate(TaskTemplateInput{Name: "", Description: "x", Goal: "y"}); !errors.Is(err, ErrTaskTemplateInvalid) {
		t.Fatalf("empty name error = %v, want %v", err, ErrTaskTemplateInvalid)
	}
	deleted, err := d.DeleteTaskTemplate(created.ID)
	if err != nil || !deleted {
		t.Fatalf("DeleteTaskTemplate = %v, %v", deleted, err)
	}
	deleted, err = d.DeleteTaskTemplate(created.ID)
	if err != nil || deleted {
		t.Fatalf("second DeleteTaskTemplate = %v, %v", deleted, err)
	}
}

func TestTaskTemplateDisjointPatchesCompose(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()

	created, err := d.CreateTaskTemplate(TaskTemplateInput{
		Name:        fmt.Sprintf("Concurrent template %d", time.Now().UnixNano()),
		Description: "initial description",
		Goal:        "initial goal",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.DeleteTaskTemplate(created.ID) })

	description := "description from concurrent patch"
	goal := "goal from concurrent patch"
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, patch := range []TaskTemplatePatch{{Description: &description}, {Goal: &goal}} {
		patch := patch
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := d.PatchTaskTemplate(created.ID, patch)
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	got, err := d.GetTaskTemplate(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Description != description || got.Goal != goal {
		t.Fatalf("disjoint patches lost an update: %+v", got)
	}
}

func TestBuiltinTaskTemplatesSeededAndProtected(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()

	listed, err := d.ListTaskTemplates()
	if err != nil {
		t.Fatal(err)
	}
	var ctf, src *TaskTemplate
	for _, tpl := range listed {
		switch tpl.Name {
		case "CTF":
			ctf = tpl
		case "SRC":
			src = tpl
		}
	}
	if ctf == nil || !ctf.Builtin {
		t.Fatalf("CTF builtin template missing: %+v", ctf)
	}
	if src == nil || !src.Builtin {
		t.Fatalf("SRC builtin template missing: %+v", src)
	}
	if !strings.Contains(src.Goal, "边界") {
		t.Fatalf("SRC goal lost its boundary emphasis")
	}

	// built-in presets cannot be deleted
	if _, err := d.DeleteTaskTemplate(ctf.ID); !errors.Is(err, ErrTaskTemplateBuiltin) {
		t.Fatalf("delete builtin err = %v, want %v", err, ErrTaskTemplateBuiltin)
	}
	if got, _ := d.GetTaskTemplate(ctf.ID); got == nil {
		t.Fatal("builtin template was deleted")
	}

	// built-in presets cannot be renamed
	renamed := "CTF-renamed"
	if _, err := d.PatchTaskTemplate(ctf.ID, TaskTemplatePatch{Name: &renamed}); !errors.Is(err, ErrTaskTemplateBuiltin) {
		t.Fatalf("rename builtin err = %v, want %v", err, ErrTaskTemplateBuiltin)
	}

	// but description/goal stay editable; restore via defer so it runs before d.Close()
	originalDesc := ctf.Description
	defer func() { _, _ = d.PatchTaskTemplate(ctf.ID, TaskTemplatePatch{Description: &originalDesc}) }()
	desc := "custom description"
	if _, err := d.PatchTaskTemplate(ctf.ID, TaskTemplatePatch{Description: &desc}); err != nil {
		t.Fatalf("edit builtin description: %v", err)
	}
	got, err := d.GetTaskTemplate(ctf.ID)
	if err != nil || got == nil || got.Description != desc {
		t.Fatalf("builtin description not updated: %+v %v", got, err)
	}
}
