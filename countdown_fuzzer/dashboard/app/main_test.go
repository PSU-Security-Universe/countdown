// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"testing"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/stretchr/testify/assert"
)

func TestOnlyManagerFilter(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.client
	build1 := testBuild(1)
	client.UploadBuild(build1)
	build2 := testBuild(2)
	client.UploadBuild(build2)

	crash1 := testCrash(build1, 1)
	crash1.Title = "only the first manager"
	client.ReportCrash(crash1)

	crash2 := testCrash(build2, 2)
	crash2.Title = "only the second manager"
	client.ReportCrash(crash2)

	crashBoth1 := testCrash(build1, 3)
	crashBoth1.Title = "both managers"
	client.ReportCrash(crashBoth1)

	crashBoth2 := testCrash(build2, 4)
	crashBoth2.Title = "both managers"
	client.ReportCrash(crashBoth2)

	// Make sure all those bugs are present on the main page.
	reply, err := c.AuthGET(AccessAdmin, "/test1")
	c.expectOK(err)
	for _, title := range []string{crash1.Title, crash2.Title, crashBoth1.Title} {
		if !bytes.Contains(reply, []byte(title)) {
			t.Fatalf("%#v is not contained on the main page", title)
		}
	}

	// Check that filtering on the main page works.
	reply, err = c.AuthGET(AccessAdmin, "/test1?only_manager="+build1.Manager)
	c.expectOK(err)
	for _, title := range []string{crash2.Title, crashBoth1.Title} {
		if bytes.Contains(reply, []byte(title)) {
			t.Fatalf("%#v is contained on the main page", title)
		}
	}
	if !bytes.Contains(reply, []byte(crash1.Title)) {
		t.Fatalf("%#v is not contained on the main page", crash1.Title)
	}

	// Invalidate all these bugs.
	polledBugs := client.pollBugs(3)
	for _, bug := range polledBugs {
		client.updateBug(bug.ID, dashapi.BugStatusInvalid, "")
	}

	// Verify that the filtering works on the invalid bugs page.
	reply, err = c.AuthGET(AccessAdmin, "/test1/invalid?only_manager="+build2.Manager)
	c.expectOK(err)
	for _, title := range []string{crash1.Title, crashBoth1.Title} {
		if bytes.Contains(reply, []byte(title)) {
			t.Fatalf("%#v is contained on the invalid bugs page", title)
		}
	}
	if !bytes.Contains(reply, []byte(crash2.Title)) {
		t.Fatalf("%#v is not contained on the invalid bugs page", crash2.Title)
	}
}

const (
	subsystemA = "subsystemA"
	subsystemB = "subsystemB"
)

func TestSubsystemFilterMain(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.client
	build := testBuild(1)
	client.UploadBuild(build)

	crash1 := testCrash(build, 1)
	crash1.Title = "first bug"
	crash1.GuiltyFiles = []string{"a.c"}
	client.ReportCrash(crash1)

	crash2 := testCrash(build, 2)
	crash2.Title = "second bug"
	crash2.GuiltyFiles = []string{"b.c"}
	client.ReportCrash(crash2)

	client.pollBugs(2)
	// Make sure all those bugs are present on the main page.
	reply, err := c.AuthGET(AccessAdmin, "/test1")
	c.expectOK(err)
	for _, title := range []string{crash1.Title, crash2.Title} {
		if !bytes.Contains(reply, []byte(title)) {
			t.Fatalf("%#v is not contained on the main page", title)
		}
	}
	// Check that filtering on the main page works.
	reply, err = c.AuthGET(AccessAdmin, "/test1?subsystem="+subsystemA)
	c.expectOK(err)
	for _, title := range []string{crash2.Title} {
		if bytes.Contains(reply, []byte(title)) {
			t.Fatalf("%#v is contained on the main page", title)
		}
	}
	if !bytes.Contains(reply, []byte(crash1.Title)) {
		t.Fatalf("%#v is not contained on the main page", crash2.Title)
	}
}

func TestSubsystemFilterTerminal(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.client
	build := testBuild(1)
	client.UploadBuild(build)

	crash1 := testCrash(build, 1)
	crash1.Title = "first bug"
	crash1.GuiltyFiles = []string{"a.c"}
	client.ReportCrash(crash1)

	crash2 := testCrash(build, 2)
	crash2.Title = "second bug"
	crash2.GuiltyFiles = []string{"b.c"}
	client.ReportCrash(crash2)

	// Invalidate all these bugs.
	polledBugs := client.pollBugs(2)
	for _, bug := range polledBugs {
		client.updateBug(bug.ID, dashapi.BugStatusInvalid, "")
	}

	// Verify that the filtering works on the invalid bugs page.
	reply, err := c.AuthGET(AccessAdmin, "/test1/invalid?subsystem="+subsystemB)
	c.expectOK(err)
	for _, title := range []string{crash1.Title} {
		if bytes.Contains(reply, []byte(title)) {
			t.Fatalf("%#v is contained on the invalid bugs page", title)
		}
	}
	if !bytes.Contains(reply, []byte(crash2.Title)) {
		t.Fatalf("%#v is not contained on the invalid bugs page", crash2.Title)
	}
}

func TestMainBugFilters(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.client
	build1 := testBuild(1)
	build1.Manager = "manager-name-123"
	client.UploadBuild(build1)

	crash1 := testCrash(build1, 1)
	crash1.Title = "my-crash-title"
	client.ReportCrash(crash1)
	client.pollBugs(1)

	// The normal main page.
	reply, err := c.AuthGET(AccessAdmin, "/test1")
	c.expectOK(err)
	assert.Contains(t, string(reply), build1.Manager)
	assert.NotContains(t, string(reply), "Applied filters")

	reply, err = c.AuthGET(AccessAdmin, "/test1?subsystem=abcd")
	c.expectOK(err)
	assert.NotContains(t, string(reply), build1.Manager) // managers are hidden
	assert.Contains(t, string(reply), "Applied filters") // we're seeing a prompt to disable the filter
	assert.NotContains(t, string(reply), crash1.Title)   // the bug does not belong to the subsystem

	reply, err = c.AuthGET(AccessAdmin, "/test1?no_subsystem=true")
	c.expectOK(err)
	assert.Contains(t, string(reply), crash1.Title) // the bug has no subsystems
}

func TestSubsystemsList(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.client
	build := testBuild(1)
	client.UploadBuild(build)

	crash1 := testCrash(build, 1)
	crash1.GuiltyFiles = []string{"a.c"}
	client.ReportCrash(crash1)
	client.pollBug()

	crash2 := testCrash(build, 2)
	crash2.GuiltyFiles = []string{"b.c"}
	client.ReportCrash(crash2)
	client.updateBug(client.pollBug().ID, dashapi.BugStatusInvalid, "")

	_, err := c.AuthGET(AccessUser, "/cron/refresh_subsystems")
	c.expectOK(err)

	reply, err := c.AuthGET(AccessAdmin, "/test1/subsystems")
	c.expectOK(err)
	assert.Contains(t, string(reply), "subsystemA")
	assert.NotContains(t, string(reply), "subsystemB")

	reply, err = c.AuthGET(AccessAdmin, "/test1/subsystems?all=true")
	c.expectOK(err)
	assert.Contains(t, string(reply), "subsystemA")
	assert.Contains(t, string(reply), "subsystemB")
}

func TestSubsystemPage(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.client
	build := testBuild(1)
	client.UploadBuild(build)

	crash1 := testCrash(build, 1)
	crash1.Title = "test crash title"
	crash1.GuiltyFiles = []string{"a.c"}
	client.ReportCrash(crash1)
	client.pollBug()

	crash2 := testCrash(build, 2)
	crash2.GuiltyFiles = []string{"b.c"}
	client.ReportCrash(crash2)
	crash2.Title = "crash that must not be present"
	client.updateBug(client.pollBug().ID, dashapi.BugStatusInvalid, "")

	reply, err := c.AuthGET(AccessAdmin, "/test1/s/subsystemA")
	c.expectOK(err)
	assert.Contains(t, string(reply), crash1.Title)
	assert.NotContains(t, string(reply), crash2.Title)
}
