/* Copyright (c) 2013-2015, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#define DEBUG
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/dma-mapping.h>
#include <linux/mutex.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/notifier.h>
//#include <soc/qcom/subsystem_restart.h>
//#include <soc/qcom/subsystem_notif.h>
#include <linux/soc/qcom/qmi.h>
//#include <soc/qcom/scm.h>
#include "msm_memshare.h"
#include "heap_mem_ext_v01.h"

/* Macros */
#define MEMSHARE_DEV_NAME "memshare"
#define MEMSHARE_CHILD_DEV_NAME "memshare_child"
static unsigned long attrs;

#define MEM_SHARE_SERVICE_SVC_ID 0x00000034
#define MEM_SHARE_SERVICE_INS_ID 1
#define MEM_SHARE_SERVICE_VERS 1

static struct qmi_handle mem_share_svc_handle;

/* Memshare Driver Structure */
struct memshare_driver {
	struct device *dev;
	struct mutex mem_share;
	struct mutex mem_free;
	struct work_struct memshare_init_work;
};

struct memshare_child {
	struct device *dev;
};

static struct memshare_driver *memsh_drv;
static struct memshare_child *memsh_child;
static struct mem_blocks memblock[MAX_CLIENTS];
static int client_table[1] = {GPS};
static uint32_t num_clients;

static int check_client(int client_id, int proc, int request)
{

	int i = 0;
	int found = DHMS_MEM_CLIENT_INVALID;
	for (i = 0; i < MAX_CLIENTS; i++) {
		if (memblock[i].client_id == client_id &&
				memblock[i].peripheral == proc) {
			found = i;
			break;
		}
	}
	if ((found == DHMS_MEM_CLIENT_INVALID) && !request) {
		pr_debug("No registered client, adding a new client\n");
		/* Add a new client */
		for (i = 0; i < MAX_CLIENTS; i++) {
			if (memblock[i].client_id == DHMS_MEM_CLIENT_INVALID) {
				memblock[i].client_id = client_id;
				memblock[i].alloted = 0;
				memblock[i].guarantee = 0;
				memblock[i].peripheral = proc;
				found = i;
				break;
			}
		}
	}

	return found;
}

void free_client(int id)
{

	memblock[id].size = 0;
	memblock[id].phy_addr = 0;
	memblock[id].virtual_addr = 0;
	memblock[id].alloted = 0;
	memblock[id].client_id = DHMS_MEM_CLIENT_INVALID;
	memblock[id].guarantee = 0;
	memblock[id].peripheral = -1;
	memblock[id].sequence_id = -1;
	memblock[id].memory_type = MEMORY_CMA;

}

void free_mem_clients(int proc)
{
	int i;

	pr_debug("memshare: freeing clients\n");

	for (i = 0; i < MAX_CLIENTS; i++) {
		if (memblock[i].peripheral == proc &&
				!memblock[i].guarantee) {
			pr_debug("Freeing memory for client id: %d\n",
					memblock[i].client_id);
			dma_free_attrs(memsh_drv->dev, memblock[i].size,
				memblock[i].virtual_addr, memblock[i].phy_addr,
				attrs);
			free_client(i);
		}
	}
}

void fill_alloc_response(struct mem_alloc_generic_resp_msg_v01 *resp,
						int id, int *flag)
{
	resp->sequence_id_valid = 1;
	resp->sequence_id = memblock[id].sequence_id;
	resp->dhms_mem_alloc_addr_info_valid = 1;
	resp->dhms_mem_alloc_addr_info_len = 1;
	resp->dhms_mem_alloc_addr_info[0].phy_addr = memblock[id].phy_addr;
	resp->dhms_mem_alloc_addr_info[0].num_bytes = memblock[id].size;
	if (!*flag) {
		resp->resp.result = QMI_RESULT_SUCCESS_V01;
		resp->resp.error = QMI_ERR_NONE_V01;
	} else {
		resp->resp.result = QMI_RESULT_FAILURE_V01;
		resp->resp.error = QMI_ERR_NO_MEMORY_V01;
	}

}

void initialize_client(void)
{
	int i;

	for (i = 0; i < MAX_CLIENTS; i++) {
		memblock[i].alloted = 0;
		memblock[i].size = 0;
		memblock[i].guarantee = 0;
		memblock[i].phy_addr = 0;
		memblock[i].virtual_addr = 0;
		memblock[i].client_id = DHMS_MEM_CLIENT_INVALID;
		memblock[i].peripheral = -1;
		memblock[i].sequence_id = -1;
		memblock[i].memory_type = MEMORY_CMA;
	}
	attrs = DMA_ATTR_NO_KERNEL_MAPPING;
}

#if 0
static int modem_notifier_cb(struct notifier_block *this, unsigned long code,
					void *_cmd)
{
	pr_debug("memshare: Modem notification\n");

	switch (code) {

	case SUBSYS_AFTER_POWERUP:
		pr_err("memshare: Modem Restart has happened\n");
		free_mem_clients(DHMS_MEM_PROC_MPSS_V01);
		break;

	default:
		pr_debug("Memshare: code: %lu\n", code);
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block nb = {
	.notifier_call = modem_notifier_cb,
};
#endif

static void handle_alloc_req(struct qmi_handle *qmi, struct sockaddr_qrtr *sq,
	   struct qmi_txn *txn, const void *decoded)
{
	struct mem_alloc_req_msg_v01 *alloc_req;
	struct mem_alloc_resp_msg_v01 alloc_resp;
	int rc = 0;

	alloc_req = (struct mem_alloc_req_msg_v01 *)decoded;
	pr_debug("%s: Received Alloc Request\n", __func__);
	pr_debug("%s: req->num_bytes = %d\n", __func__, alloc_req->num_bytes);
	mutex_lock(&memsh_drv->mem_share);
	if (!memblock[GPS].size) {
		memset(&alloc_resp, 0, sizeof(struct mem_alloc_resp_msg_v01));
		alloc_resp.resp = QMI_RESULT_FAILURE_V01;
		rc = memshare_alloc(memsh_drv->dev, alloc_req->num_bytes,
					&memblock[GPS]);
	}
	alloc_resp.num_bytes_valid = 1;
	alloc_resp.num_bytes =  alloc_req->num_bytes;
	alloc_resp.handle_valid = 1;
	alloc_resp.handle = memblock[GPS].phy_addr;
	/* Binding last client to support request coming on old idl*/
	if (rc) {
		alloc_resp.resp = QMI_RESULT_FAILURE_V01;
		memblock[GPS].size = 0;
	} else {
		alloc_resp.resp = QMI_RESULT_SUCCESS_V01;
	}

	mutex_unlock(&memsh_drv->mem_share);

	pr_debug("alloc_resp.num_bytes :%d, alloc_resp.handle :%lx, alloc_resp.mem_req_result :%lx\n",
			  alloc_resp.num_bytes,
			  (unsigned long int)alloc_resp.handle,
			  (unsigned long int)alloc_resp.resp);
	rc = qmi_send_response(qmi, sq, txn, MEM_ALLOC_RESP_MSG_V01, MEM_ALLOC_REQ_MAX_MSG_LEN_V01,
			mem_alloc_resp_msg_data_v01_ei, &alloc_resp);
	if (rc < 0)
		pr_err("In %s, Error sending the alloc request: %d\n",
					__func__, rc);
}

static void handle_alloc_generic_req(struct qmi_handle *qmi, struct sockaddr_qrtr *sq,
	   struct qmi_txn *txn, const void *decoded)
{
	struct mem_alloc_generic_req_msg_v01 *alloc_req;
	struct mem_alloc_generic_resp_msg_v01 *alloc_resp;
	int rc, resp = 0;
	int client_id;

	alloc_req = (struct mem_alloc_generic_req_msg_v01 *)decoded;
	pr_debug("%s: Received Alloc Request\n", __func__);
	pr_debug("%s: req->num_bytes = %d\n", __func__, alloc_req->num_bytes);
	mutex_lock(&memsh_drv->mem_share);
	alloc_resp = kzalloc(sizeof(struct mem_alloc_generic_resp_msg_v01),
					GFP_KERNEL);
	if (!alloc_resp) {
		pr_err("In %s, error allocating memory to response structure\n",
						__func__);
		mutex_unlock(&memsh_drv->mem_share);
		return;
	}
	alloc_resp->resp.result = QMI_RESULT_FAILURE_V01;
	alloc_resp->resp.error = QMI_ERR_NO_MEMORY_V01;
	pr_debug("alloc request client id: %d proc _id: %d\n",
			alloc_req->client_id, alloc_req->proc_id);
	client_id = check_client(alloc_req->client_id, alloc_req->proc_id,
								CHECK);

	if (client_id >= MAX_CLIENTS) {
		pr_err("memshare: %s client not found, requested client: %d, proc_id: %d\n",
			__func__, alloc_req->client_id,
			alloc_req->proc_id);
		return;
	}

	if (!memblock[client_id].alloted) {
		rc = memshare_alloc(memsh_drv->dev, alloc_req->num_bytes,
					&memblock[client_id]);
		if (rc) {
			pr_err("In %s,Unable to allocate memory for requested client\n",
							__func__);
			resp = 1;
		}
		if (!resp) {
			memblock[client_id].alloted = 1;
			memblock[client_id].size = alloc_req->num_bytes;
			memblock[client_id].peripheral = alloc_req->proc_id;
		}
	}
	memblock[client_id].sequence_id = alloc_req->sequence_id;

	fill_alloc_response(alloc_resp, client_id, &resp);

	mutex_unlock(&memsh_drv->mem_share);
	pr_debug("alloc_resp.num_bytes :%d, alloc_resp.handle :%lx, alloc_resp.mem_req_result :%lx\n",
			  alloc_resp->dhms_mem_alloc_addr_info[0].num_bytes,
			  (unsigned long int)
			  alloc_resp->dhms_mem_alloc_addr_info[0].phy_addr,
			  (unsigned long int)alloc_resp->resp.result);
	rc = qmi_send_response(qmi, sq, txn, MEM_ALLOC_GENERIC_RESP_MSG_V01, MEM_ALLOC_REQ_MAX_MSG_LEN_V01,
			mem_alloc_generic_resp_msg_data_v01_ei, alloc_resp);

	if (rc < 0)
		pr_err("In %s, Error sending the alloc request: %d\n",
							__func__, rc);
}

static void handle_free_req(struct qmi_handle *qmi, struct sockaddr_qrtr *sq,
	   struct qmi_txn *txn, const void *decoded)
{
	struct mem_free_req_msg_v01 *free_req;
	struct mem_free_resp_msg_v01 free_resp;
	int rc;

	mutex_lock(&memsh_drv->mem_free);
	if (!memblock[GPS].guarantee) {
		free_req = (struct mem_free_req_msg_v01 *)decoded;
		pr_debug("%s: Received Free Request\n", __func__);
		memset(&free_resp, 0, sizeof(struct mem_free_resp_msg_v01));
		pr_debug("In %s: pblk->virtual_addr :%lx, pblk->phy_addr: %lx\n,size: %d",
				__func__,
			(unsigned long int)memblock[GPS].virtual_addr,
			(unsigned long int)free_req->handle,
			memblock[GPS].size);
		dma_free_coherent(memsh_drv->dev, memblock[GPS].size,
			memblock[GPS].virtual_addr,
				free_req->handle);
	}
	free_resp.resp = QMI_RESULT_SUCCESS_V01;
	mutex_unlock(&memsh_drv->mem_free);
	rc = qmi_send_response(qmi, sq, txn, MEM_FREE_RESP_MSG_V01, MEM_FREE_REQ_MAX_MSG_LEN_V01,
			mem_free_resp_msg_data_v01_ei, &free_resp);
	if (rc < 0)
		pr_err("In %s, Error sending the free request: %d\n",
					__func__, rc);
}

static void handle_free_generic_req(struct qmi_handle *qmi, struct sockaddr_qrtr *sq,
	   struct qmi_txn *txn, const void *decoded)
{
	struct mem_free_generic_req_msg_v01 *free_req;
	struct mem_free_generic_resp_msg_v01 free_resp;
	int rc;
	int flag = 0;
	uint32_t client_id;

	free_req = (struct mem_free_generic_req_msg_v01 *)decoded;
	pr_debug("%s: Received Free Request\n", __func__);
	mutex_lock(&memsh_drv->mem_free);
	memset(&free_resp, 0, sizeof(struct mem_free_generic_resp_msg_v01));
	free_resp.resp.error = QMI_ERR_INTERNAL_V01;
	free_resp.resp.result = QMI_RESULT_FAILURE_V01;
	pr_debug("Client id: %d proc id: %d\n", free_req->client_id,
				free_req->proc_id);
	client_id = check_client(free_req->client_id, free_req->proc_id, FREE);
	if (client_id == DHMS_MEM_CLIENT_INVALID) {
		pr_err("In %s, Invalid client request to free memory\n",
					__func__);
		flag = 1;
	} else if (!memblock[client_id].guarantee &&
					memblock[client_id].alloted) {
		pr_debug("In %s: pblk->virtual_addr :%lx, pblk->phy_addr: %lx\n,size: %d",
				__func__,
				(unsigned long int)
				memblock[client_id].virtual_addr,
				(unsigned long int)memblock[client_id].phy_addr,
				memblock[client_id].size);
		dma_free_attrs(memsh_drv->dev, memblock[client_id].size,
			memblock[client_id].virtual_addr,
			memblock[client_id].phy_addr,
			attrs);
		free_client(client_id);
	} else {
		pr_err("In %s, Request came for a guaranteed client cannot free up the memory\n",
						__func__);
	}

	if (flag) {
		free_resp.resp.result = QMI_RESULT_FAILURE_V01;
		free_resp.resp.error = QMI_ERR_INVALID_ID_V01;
	} else {
		free_resp.resp.result = QMI_RESULT_SUCCESS_V01;
		free_resp.resp.error = QMI_ERR_NONE_V01;
	}

	mutex_unlock(&memsh_drv->mem_free);
	rc = qmi_send_response(qmi, sq, txn, MEM_FREE_GENERIC_RESP_MSG_V01, MEM_FREE_REQ_MAX_MSG_LEN_V01,
			mem_free_generic_resp_msg_data_v01_ei, &free_resp);

	if (rc < 0)
		pr_err("In %s, Error sending the free request: %d\n",
					__func__, rc);
}

static struct qmi_msg_handler mem_share_msg_handlers[] = {
	{
		.type = QMI_REQUEST,
		.msg_id = MEM_ALLOC_REQ_MSG_V01,
		.ei = mem_alloc_req_msg_data_v01_ei,
		.decoded_size = sizeof(struct mem_alloc_req_msg_v01),
		.fn = handle_alloc_req,
	},
	{
		.type = QMI_REQUEST,
		.msg_id = MEM_FREE_REQ_MSG_V01,
		.ei = mem_free_req_msg_data_v01_ei,
		.decoded_size = sizeof(struct mem_alloc_req_msg_v01),
		.fn = handle_free_req,
	},
	{
		.type = QMI_REQUEST,
		.msg_id = MEM_ALLOC_GENERIC_REQ_MSG_V01,
		.ei = mem_alloc_generic_req_msg_data_v01_ei,
		.decoded_size = sizeof(struct mem_alloc_req_msg_v01),
		.fn = handle_alloc_generic_req,
	},
	{
		.type = QMI_REQUEST,
		.msg_id = MEM_FREE_GENERIC_REQ_MSG_V01,
		.ei = mem_free_generic_req_msg_data_v01_ei,
		.decoded_size = sizeof(struct mem_alloc_req_msg_v01),
		.fn = handle_free_generic_req,
	},
	{}
};

static struct qmi_ops mem_share_svc_ops = {};

int memshare_alloc(struct device *dev,
					unsigned int block_size,
					struct mem_blocks *pblk)
{

	int ret;

	pr_debug("%s: memshare_alloc called", __func__);
	if (!pblk) {
		pr_err("%s: Failed to alloc\n", __func__);
		return -ENOMEM;
	}

	pblk->virtual_addr = dma_alloc_attrs(dev, block_size,
						&pblk->phy_addr, GFP_KERNEL,
						attrs);
	if (pblk->virtual_addr == NULL) {
		pr_err("allocation failed, %d\n", block_size);
		ret = -ENOMEM;
		return ret;
	}
	pr_debug("pblk->phy_addr :%lx, pblk->virtual_addr %lx\n",
		  (unsigned long int)pblk->phy_addr,
		  (unsigned long int)pblk->virtual_addr);
	return 0;
}

static int memshare_child_probe(struct platform_device *pdev)
{
	int rc;
	uint32_t size;
	const char *name;
	struct memshare_child *drv;

	drv = devm_kzalloc(&pdev->dev, sizeof(struct memshare_child),
							GFP_KERNEL);

	if (!drv) {
		pr_err("Unable to allocate memory to driver\n");
		return -ENOMEM;
	}

	drv->dev = &pdev->dev;
	memsh_child = drv;
	platform_set_drvdata(pdev, memsh_child);

	rc = of_property_read_u32(pdev->dev.of_node, "qcom,peripheral-size",
						&size);
	if (rc) {
		pr_err("In %s, Error reading size of clients\n",
				__func__);
		return rc;
	}

	rc = of_property_read_string(pdev->dev.of_node, "label",
						&name);
	if (rc) {
		pr_err("In %s, Error reading peripheral info for client\n",
					__func__);
		return rc;
	}

	if (strcmp(name, "modem") == 0)
		memblock[num_clients].peripheral = DHMS_MEM_PROC_MPSS_V01;
	else if (strcmp(name, "adsp") == 0)
		memblock[num_clients].peripheral = DHMS_MEM_PROC_ADSP_V01;
	else if (strcmp(name, "wcnss") == 0)
		memblock[num_clients].peripheral = DHMS_MEM_PROC_WCNSS_V01;

	memblock[num_clients].size = size;
	memblock[num_clients].client_id = client_table[num_clients];
	memblock[num_clients].guarantee = 1;

	rc = memshare_alloc(memsh_child->dev, memblock[num_clients].size,
					&memblock[num_clients]);
	if (rc) {
		pr_err("In %s, Unable to allocate memory for guaranteed clients\n",
						__func__);
		return rc;
	}
	memblock[num_clients].alloted = 1;
	num_clients++;

	return 0;
}

static int memshare_probe(struct platform_device *pdev)
{
	int rc;
	struct memshare_driver *drv;

	rc = qmi_handle_init(&mem_share_svc_handle, 255, &mem_share_svc_ops, mem_share_msg_handlers);
	if (rc < 0) {
		pr_err("%s: qmi_handle_init() failed: %d\n", __func__, rc);
		return rc;
	}

	drv = devm_kzalloc(&pdev->dev, sizeof(struct memshare_driver),
							GFP_KERNEL);

	if (!drv) {
		pr_err("Unable to allocate memory to driver\n");
		return -ENOMEM;
	}

	/* Memory allocation has been done successfully */
	mutex_init(&drv->mem_free);
	mutex_init(&drv->mem_share);

	drv->dev = &pdev->dev;
	memsh_drv = drv;
	platform_set_drvdata(pdev, memsh_drv);
	initialize_client();
	num_clients = 0;

	rc = of_platform_populate(pdev->dev.of_node, NULL, NULL, &pdev->dev);

	if (rc) {
		pr_err("In %s, error populating the devices\n", __func__);
		return rc;
	}

	rc = qmi_add_server(&mem_share_svc_handle, MEM_SHARE_SERVICE_SVC_ID, MEM_SHARE_SERVICE_VERS, MEM_SHARE_SERVICE_INS_ID);
	if (rc < 0) {
		pr_err("%s: qmi_add_server() failed: %d\n", __func__, rc);
		return rc;
	}

	//subsys_notif_register_notifier("modem", &nb);
	pr_info("In %s, Memshare probe success\n", __func__);
	return 0;
}

static int memshare_remove(struct platform_device *pdev)
{
	if (!memsh_drv)
		return 0;

	qmi_handle_release(&mem_share_svc_handle);

	return 0;
}

static int memshare_child_remove(struct platform_device *pdev)
{
	if (!memsh_child)
		return 0;

	return 0;
}

static struct of_device_id memshare_match_table[] = {
	{
		.compatible = "qcom,memshare",
	},
	{}
};

static struct of_device_id memshare_match_table1[] = {
	{
		.compatible = "qcom,memshare-peripheral",
	},
	{}
};


static struct platform_driver memshare_pdriver = {
	.probe          = memshare_probe,
	.remove         = memshare_remove,
	.driver = {
		.name   = MEMSHARE_DEV_NAME,
		.owner  = THIS_MODULE,
		.of_match_table = memshare_match_table,
	},
};

static struct platform_driver memshare_pchild = {
	.probe          = memshare_child_probe,
	.remove         = memshare_child_remove,
	.driver = {
		.name   = MEMSHARE_CHILD_DEV_NAME,
		.owner  = THIS_MODULE,
		.of_match_table = memshare_match_table1,
	},
};

module_platform_driver(memshare_pdriver);
module_platform_driver(memshare_pchild);

MODULE_DESCRIPTION("Mem Share QMI Service Driver");
MODULE_LICENSE("GPL v2");
