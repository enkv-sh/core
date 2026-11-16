package core

import (
	"testing"
	"testing/synctest"
)

// full_only: false
func TestApplyPublicationCloseWaitsForOwnedPublication(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		disposed := make(chan struct{})
		engine := &InstalledApply{installation: ApplyInstallation{CloseInstalled: func() { close(disposed) }}}
		capture := &applyPublicationCapture{}
		defer capture.close()
		_, done, admitted := engine.beginApplyInvocation(capture)
		if !admitted {
			t.Fatal("combined invocation did not acquire its owner")
		}
		engine.endApplyInvocation(done, capture)
		returned := make(chan struct{})
		go func() {
			engine.Close()
			close(returned)
		}()
		synctest.Wait()
		select {
		case <-disposed:
			t.Fatal("Close disposed the route before publication ended")
		default:
		}
		select {
		case <-returned:
			t.Fatal("Close returned before publication ended")
		default:
		}
		capture.close()
		synctest.Wait()
		for _, ended := range []<-chan struct{}{done, returned, disposed} {
			select {
			case <-ended:
			default:
				t.Fatal("publication release did not complete owned cleanup")
			}
		}
	})
}
