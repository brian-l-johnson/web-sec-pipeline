package jobs

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	k8stypes "k8s.io/apimachinery/pkg/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

const (
	labelJobType = "web-sec-tools/job-type"
	labelJobID   = "web-sec-tools/job-id"
	labelTool    = "web-sec-tools/tool"
	jobTypeValue = "scan"
)

// JobEventHandler is called when a Kubernetes Job changes state.
type JobEventHandler interface {
	OnJobComplete(jobID uuid.UUID, tool string)
	OnJobFailed(jobID uuid.UUID, tool string, logs string)
}

// Manager creates and watches Kubernetes Jobs for web scan tools.
type Manager struct {
	clientset    *kubernetes.Clientset
	crawlerImage string
	zapImage     string
	nucleiImage  string
	namespace    string
	pvcName      string
	// handled guards against duplicate event dispatch: the informer fires
	// UpdateFunc on every k8s Job update (TTL controller, metadata patches, etc.)
	// even after a Job has reached a terminal state. LoadOrStore ensures each
	// job+tool pair is dispatched to the handler exactly once.
	handled sync.Map // key: "<jobID>/<tool>", value: struct{}
}

// NewManager creates a Manager using in-cluster config and the given image refs.
// namespace and pvcName default to "web-sec-tools" and "web-sec-tools-data" if empty.
func NewManager(crawlerImage, zapImage, nucleiImage, namespace, pvcName string) (*Manager, error) {
	if namespace == "" {
		namespace = "web-sec-tools"
	}
	if pvcName == "" {
		pvcName = "web-sec-tools-data"
	}
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in-cluster config: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create kubernetes clientset: %w", err)
	}
	return &Manager{
		clientset:    clientset,
		crawlerImage: crawlerImage,
		zapImage:     zapImage,
		nucleiImage:  nucleiImage,
		namespace:    namespace,
		pvcName:      pvcName,
	}, nil
}

// CreateCrawlJob launches the Playwright+mitmproxy crawler Job for a given scan job.
// The crawler writes its HAR output to /data/output/<jobID>/crawl/capture.har.
// If auth_config is provided it is stored in a k8s Secret mounted into the pod
// rather than passed as a plain environment variable.
func (m *Manager) CreateCrawlJob(ctx context.Context, jobID uuid.UUID, targetURL string, scope []string, authConfig json.RawMessage) error {
	outputDir := fmt.Sprintf("/data/output/%s/crawl", jobID)
	scopeJSON, _ := json.Marshal(scope)

	env := []corev1.EnvVar{
		{Name: "TARGET_URL", Value: targetURL},
		{Name: "SCOPE", Value: string(scopeJSON)},
		{Name: "OUTPUT_DIR", Value: outputDir},
	}

	// Store credentials in a k8s Secret so they are not visible in pod env.
	var authSecretName string
	if len(authConfig) > 0 && string(authConfig) != "null" {
		var err error
		authSecretName, err = m.createAuthSecret(ctx, jobID, authConfig)
		if err != nil {
			return fmt.Errorf("create auth secret: %w", err)
		}
		env = append(env, corev1.EnvVar{
			Name:  "AUTH_CONFIG_PATH",
			Value: "/run/secrets/auth-config/auth_config.json",
		})
	}

	job := m.buildJob(jobID, "crawl", m.crawlerImage, env,
		corev1.ResourceList{
			corev1.ResourceMemory: resource.MustParse("512Mi"),
			corev1.ResourceCPU:    resource.MustParse("500m"),
		},
		corev1.ResourceList{
			corev1.ResourceMemory: resource.MustParse("2Gi"),
			corev1.ResourceCPU:    resource.MustParse("2"),
		},
		// Crawl jobs need a longer deadline — authenticated crawls can be slow.
		1800,
	)

	if authSecretName != "" {
		optional := false
		job.Spec.Template.Spec.Volumes = append(job.Spec.Template.Spec.Volumes, corev1.Volume{
			Name: "auth-secret",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: authSecretName,
					Optional:   &optional,
				},
			},
		})
		job.Spec.Template.Spec.Containers[0].VolumeMounts = append(
			job.Spec.Template.Spec.Containers[0].VolumeMounts,
			corev1.VolumeMount{Name: "auth-secret", MountPath: "/run/secrets/auth-config", ReadOnly: true},
		)
	}

	created, err := m.clientset.BatchV1().Jobs(m.namespace).Create(ctx, job, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create crawl job: %w", err)
	}

	if authSecretName != "" {
		if err := m.setSecretOwner(ctx, authSecretName, created); err != nil {
			// Non-fatal: secret won't auto-GC but the scan is unaffected.
			log.Printf("jobs: set ownerRef on auth secret failed (job=%s): %v", jobID, err)
		}
	}
	return nil
}

// createAuthSecret creates a k8s Secret containing the auth config JSON.
func (m *Manager) createAuthSecret(ctx context.Context, jobID uuid.UUID, authConfig json.RawMessage) (string, error) {
	name := fmt.Sprintf("web-crawl-auth-%s", jobID)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: m.namespace,
			Labels: map[string]string{
				labelJobType: jobTypeValue,
				labelJobID:   jobID.String(),
			},
		},
		Data: map[string][]byte{
			"auth_config.json": []byte(authConfig),
		},
	}
	if _, err := m.clientset.CoreV1().Secrets(m.namespace).Create(ctx, secret, metav1.CreateOptions{}); err != nil {
		return "", fmt.Errorf("create secret: %w", err)
	}
	return name, nil
}

// setSecretOwner patches the Secret with an ownerReference pointing to the Job
// so Kubernetes garbage-collects the Secret when the Job TTLs out.
func (m *Manager) setSecretOwner(ctx context.Context, secretName string, job *batchv1.Job) error {
	isController := true
	blockDeletion := true
	patch, err := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"ownerReferences": []map[string]any{{
				"apiVersion":         "batch/v1",
				"kind":               "Job",
				"name":               job.Name,
				"uid":                string(job.UID),
				"controller":         &isController,
				"blockOwnerDeletion": &blockDeletion,
			}},
		},
	})
	if err != nil {
		return err
	}
	_, err = m.clientset.CoreV1().Secrets(m.namespace).Patch(
		ctx, secretName, k8stypes.MergePatchType, patch, metav1.PatchOptions{},
	)
	return err
}

// Healthy returns true if the underlying Kubernetes API is reachable.
func (m *Manager) Healthy() bool {
	_, err := m.clientset.Discovery().ServerVersion()
	return err == nil
}

// CreateZAPJob launches a ZAP active/passive scan Job.
// Called by the orchestrator after the crawl completes (Phase 5).
func (m *Manager) CreateZAPJob(ctx context.Context, jobID uuid.UUID, targetURL, scanProfile string) error {
	outputDir := fmt.Sprintf("/data/output/%s/zap", jobID)

	env := []corev1.EnvVar{
		{Name: "TARGET_URL", Value: targetURL},
		{Name: "SCAN_PROFILE", Value: scanProfile},
		{Name: "OUTPUT_DIR", Value: outputDir},
	}

	job := m.buildJob(jobID, "zap", m.zapImage, env,
		corev1.ResourceList{
			corev1.ResourceMemory: resource.MustParse("1Gi"),
			corev1.ResourceCPU:    resource.MustParse("500m"),
		},
		corev1.ResourceList{
			corev1.ResourceMemory: resource.MustParse("4Gi"),
			corev1.ResourceCPU:    resource.MustParse("2"),
		},
		3600,
	)

	if _, err := m.clientset.BatchV1().Jobs(m.namespace).Create(ctx, job, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("create zap job: %w", err)
	}
	return nil
}

// CreateNucleiJob launches a Nuclei template scan Job.
// Called by the orchestrator after the crawl completes (Phase 6).
func (m *Manager) CreateNucleiJob(ctx context.Context, jobID uuid.UUID, targetURL string) error {
	outputDir := fmt.Sprintf("/data/output/%s/nuclei", jobID)

	env := []corev1.EnvVar{
		{Name: "TARGET_URL", Value: targetURL},
		{Name: "OUTPUT_DIR", Value: outputDir},
	}

	job := m.buildJob(jobID, "nuclei", m.nucleiImage, env,
		corev1.ResourceList{
			corev1.ResourceMemory: resource.MustParse("512Mi"),
			corev1.ResourceCPU:    resource.MustParse("500m"),
		},
		corev1.ResourceList{
			corev1.ResourceMemory: resource.MustParse("2Gi"),
			corev1.ResourceCPU:    resource.MustParse("2"),
		},
		3600,
	)

	if _, err := m.clientset.BatchV1().Jobs(m.namespace).Create(ctx, job, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("create nuclei job: %w", err)
	}
	return nil
}

func (m *Manager) buildJob(jobID uuid.UUID, tool, image string, env []corev1.EnvVar, requests, limits corev1.ResourceList, deadlineSeconds int64) *batchv1.Job {
	ttl := int32(3600)
	backoff := int32(0) // no retries — a single failure immediately marks the Job Failed
	runAsNonRoot := true
	runAsUser := int64(1000)

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("web-%s-%s", tool, jobID),
			Namespace: m.namespace,
			Labels: map[string]string{
				labelJobType: jobTypeValue,
				labelJobID:   jobID.String(),
				labelTool:    tool,
			},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:            &backoff,
			TTLSecondsAfterFinished: &ttl,
			ActiveDeadlineSeconds:   &deadlineSeconds,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						labelJobType: jobTypeValue,
						labelJobID:   jobID.String(),
						labelTool:    tool,
					},
				},
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyNever,
					ImagePullSecrets: []corev1.LocalObjectReference{
						{Name: "ghcr-pull-secret"},
					},
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: &runAsNonRoot,
						RunAsUser:    &runAsUser,
					},
					Volumes: []corev1.Volume{
						{
							Name: "data",
							VolumeSource: corev1.VolumeSource{
								PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
									ClaimName: m.pvcName,
								},
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name:  tool,
							Image: image,
							Env:   env,
							Resources: corev1.ResourceRequirements{
								Requests: requests,
								Limits:   limits,
							},
							VolumeMounts: []corev1.VolumeMount{
								{Name: "data", MountPath: "/data"},
							},
						},
					},
				},
			},
		},
	}
}

// WatchJobs uses a SharedInformer to watch scan Jobs and notify the handler.
func (m *Manager) WatchJobs(ctx context.Context, handler JobEventHandler) {
	labelSelector := labels.SelectorFromSet(labels.Set{
		labelJobType: jobTypeValue,
	})

	factory := informers.NewSharedInformerFactoryWithOptions(
		m.clientset,
		30*time.Second,
		informers.WithNamespace(m.namespace),
		informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
			opts.LabelSelector = labelSelector.String()
		}),
	)

	jobInformer := factory.Batch().V1().Jobs().Informer()
	// Only use UpdateFunc, not AddFunc. AddFunc fires for all existing jobs when
	// the informer cache populates on startup, which would re-fire OnJobFailed for
	// jobs the orchestrator already processed. ReconcileRunningJobs handles startup
	// state sync explicitly instead.
	jobInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(_, newObj interface{}) {
			job, ok := newObj.(*batchv1.Job)
			if !ok {
				return
			}
			m.handleJobUpdate(ctx, job, handler)
		},
	})

	factory.Start(ctx.Done())
	factory.WaitForCacheSync(ctx.Done())
	<-ctx.Done()
}

func (m *Manager) handleJobUpdate(ctx context.Context, job *batchv1.Job, handler JobEventHandler) {
	jobIDStr, ok := job.Labels[labelJobID]
	if !ok {
		return
	}
	tool, ok := job.Labels[labelTool]
	if !ok {
		return
	}
	jobID, err := uuid.Parse(jobIDStr)
	if err != nil {
		log.Printf("jobs: invalid job-id label %q: %v", jobIDStr, err)
		return
	}

	key := jobID.String() + "/" + tool
	for _, cond := range job.Status.Conditions {
		if cond.Type == batchv1.JobComplete && cond.Status == corev1.ConditionTrue {
			if _, dup := m.handled.LoadOrStore(key, struct{}{}); !dup {
				handler.OnJobComplete(jobID, tool)
			}
			return
		}
		if cond.Type == batchv1.JobFailed && cond.Status == corev1.ConditionTrue {
			if _, dup := m.handled.LoadOrStore(key, struct{}{}); !dup {
				logs := m.fetchPodLogs(ctx, job)
				handler.OnJobFailed(jobID, tool, logs)
			}
			return
		}
	}
}

func (m *Manager) fetchPodLogs(ctx context.Context, job *batchv1.Job) string {
	selector := labels.SelectorFromSet(job.Spec.Selector.MatchLabels)
	pods, err := m.clientset.CoreV1().Pods(m.namespace).List(ctx, metav1.ListOptions{
		LabelSelector: selector.String(),
	})
	if err != nil {
		return fmt.Sprintf("(error listing pods: %v)", err)
	}
	if len(pods.Items) == 0 {
		return "(no pods found)"
	}

	pod := pods.Items[0]
	containerName := ""
	if len(pod.Spec.Containers) > 0 {
		containerName = pod.Spec.Containers[0].Name
	}

	req := m.clientset.CoreV1().Pods(m.namespace).GetLogs(pod.Name, &corev1.PodLogOptions{
		Container: containerName,
	})
	rc, err := req.Stream(ctx)
	if err != nil {
		return fmt.Sprintf("(error streaming logs: %v)", err)
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		return fmt.Sprintf("(error reading logs: %v)", err)
	}
	return string(data)
}

// ReconcileRunningJobs checks k8s state for jobs the DB thinks are running.
// It only calls event handlers for jobs that have a terminal k8s condition.
// If a tool's k8s Job is missing (e.g. TTL expired) it is skipped — it was
// most likely already processed before the coordinator restarted.
func (m *Manager) ReconcileRunningJobs(ctx context.Context, runningJobs []uuid.UUID, handler JobEventHandler) error {
	for _, jobID := range runningJobs {
		for _, tool := range []string{"crawl", "zap", "nuclei"} {
			k8sJobName := fmt.Sprintf("web-%s-%s", tool, jobID)
			k8sJob, err := m.clientset.BatchV1().Jobs(m.namespace).Get(ctx, k8sJobName, metav1.GetOptions{})
			if err != nil {
				// Job not found — likely TTL-expired after it already completed/failed.
				// Skip rather than spuriously marking it failed again.
				log.Printf("reconcile: k8s job %s not found (likely TTL-expired), skipping", k8sJobName)
				continue
			}
			key := jobID.String() + "/" + tool
			for _, cond := range k8sJob.Status.Conditions {
				if cond.Type == batchv1.JobComplete && cond.Status == corev1.ConditionTrue {
					if _, dup := m.handled.LoadOrStore(key, struct{}{}); !dup {
						handler.OnJobComplete(jobID, tool)
					}
				} else if cond.Type == batchv1.JobFailed && cond.Status == corev1.ConditionTrue {
					if _, dup := m.handled.LoadOrStore(key, struct{}{}); !dup {
						logs := m.fetchPodLogs(ctx, k8sJob)
						handler.OnJobFailed(jobID, tool, logs)
					}
				}
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Log streaming
// ---------------------------------------------------------------------------

// LogLine is one line of output from a scan pod, tagged with the tool name.
type LogLine struct {
	Tool string `json:"tool"`
	Text string `json:"text"`
}

// logPollInterval is how often we retry when a pod/job hasn't appeared yet.
const logPollInterval = 3 * time.Second

// logMaxWait is the longest we'll wait for a tool's k8s Job to be created
// (worst case: crawl runs its full 30-min deadline before ZAP/Nuclei start).
const logMaxWait = 90 * time.Minute

// StreamJobLogs fans out to all three scan tools in parallel, sending each
// log line to out. The channel is closed when all tools have finished (or the
// context is cancelled). Callers must drain out until it is closed.
func (m *Manager) StreamJobLogs(ctx context.Context, jobID uuid.UUID, out chan<- LogLine) {
	defer close(out)
	var wg sync.WaitGroup
	for _, tool := range []string{"crawl", "zap", "nuclei"} {
		wg.Add(1)
		go func(t string) {
			defer wg.Done()
			m.streamToolLogs(ctx, jobID, t, out)
		}(tool)
	}
	wg.Wait()
}

// streamToolLogs waits for the k8s Job for tool to exist, then streams its
// pod logs into out. Returns when logs are exhausted or ctx is cancelled.
func (m *Manager) streamToolLogs(ctx context.Context, jobID uuid.UUID, tool string, out chan<- LogLine) {
	jobName := fmt.Sprintf("web-%s-%s", tool, jobID)
	deadline := time.Now().Add(logMaxWait)

	// Wait for the k8s Job to be created.
	var k8sJob *batchv1.Job
	for {
		j, err := m.clientset.BatchV1().Jobs(m.namespace).Get(ctx, jobName, metav1.GetOptions{})
		if err == nil {
			k8sJob = j
			break
		}
		if !k8serrors.IsNotFound(err) {
			return // unexpected API error
		}
		if time.Now().After(deadline) {
			send(ctx, out, LogLine{Tool: "system", Text: fmt.Sprintf("[%s] logs unavailable — job not found within timeout", tool)})
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(logPollInterval):
		}
	}

	// Wait for a pod to be scheduled for the job.
	selector := labels.SelectorFromSet(k8sJob.Spec.Selector.MatchLabels)
	podDeadline := time.Now().Add(2 * time.Minute)
	var podName, containerName string
	for {
		pods, err := m.clientset.CoreV1().Pods(m.namespace).List(ctx, metav1.ListOptions{
			LabelSelector: selector.String(),
		})
		if err == nil && len(pods.Items) > 0 {
			pod := pods.Items[0]
			podName = pod.Name
			if len(pod.Spec.Containers) > 0 {
				containerName = pod.Spec.Containers[0].Name
			}
			break
		}
		if time.Now().After(podDeadline) {
			send(ctx, out, LogLine{Tool: "system", Text: fmt.Sprintf("[%s] pod not found", tool)})
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}

	// Stream the pod logs, following until the container exits.
	req := m.clientset.CoreV1().Pods(m.namespace).GetLogs(podName, &corev1.PodLogOptions{
		Container: containerName,
		Follow:    true,
	})
	stream, err := req.Stream(ctx)
	if err != nil {
		return
	}
	defer stream.Close()

	sc := bufio.NewScanner(stream)
	sc.Buffer(make([]byte, 256*1024), 256*1024) // ZAP can emit very long lines
	for sc.Scan() {
		if !send(ctx, out, LogLine{Tool: tool, Text: sc.Text()}) {
			return
		}
	}
}

// send writes a LogLine to out, respecting context cancellation.
// Returns false if the context was cancelled before the send succeeded.
func send(ctx context.Context, out chan<- LogLine, line LogLine) bool {
	select {
	case out <- line:
		return true
	case <-ctx.Done():
		return false
	}
}
