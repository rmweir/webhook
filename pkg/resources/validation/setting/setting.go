package setting

import (
	"github.com/rancher/wrangler/pkg/webhook"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/trace"
	"net/http"
	"time"
)

func NewValidator() webhook.Handler {
	return &settingValidator{}
}

type settingValidator struct{}

func (grv *settingValidator) Admit(response *webhook.Response, request *webhook.Request) error {
	listTrace := trace.New("settingValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(2 * time.Second)

	if request.Operation == "DELETE" {
		response.Result = &metav1.Status{
			Status:  "Failure",
			Message: "Cannot delete Settings",
			Reason:  metav1.StatusReasonBadRequest,
			Code:    http.StatusBadRequest,
		}
		response.Allowed = false
		return nil
	}

	response.Allowed = true
	return nil
}

