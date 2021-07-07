/*
 * Copyright (c) 2019-2021 Two Sigma Open Source, LLC
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* Python extension.
 *
 * You probably just want to use ctypes. We have a need for this in a
 * context where a) ctypes isn't available and b) <Python.h> isn't
 * easily available, so we match the ABI by hand and make sure to only
 * use stuff from Py_LIMITED_ABI.
 */

#include <sys/types.h>
#include <stddef.h>

/* We only use pointers to this */
typedef struct PyObject PyObject;

/* methodobject.h */
typedef PyObject *(*PyCFunction)(PyObject *, PyObject *);
struct PyMethodDef {
    const char  *ml_name;
    PyCFunction ml_meth;
    int         ml_flags;
    const char  *ml_doc;
};
typedef struct PyMethodDef PyMethodDef;
#define METH_VARARGS  0x0001

/* object.h */
typedef int (*inquiry)(PyObject *);
typedef int (*visitproc)(PyObject *, void *);
typedef int (*traverseproc)(PyObject *, visitproc, void *);
typedef void (*freefunc)(void *);

/* object.h + moduleobject.h */
struct PyModuleDef {
    ssize_t ob_refcnt;
    struct _typeobject *ob_type;
    PyObject* (*m_init)(void);
    ssize_t m_index;
    PyObject* m_copy;
    const char* m_name;
    const char* m_doc;
    ssize_t m_size;
    PyMethodDef *m_methods;
    struct PyModuleDef_Slot* m_slots;
    traverseproc m_traverse;
    inquiry m_clear;
    freefunc m_free;
};

/* modsupport.h */
int PyArg_ParseTuple(PyObject *, const char *, ...);
PyObject *PyModule_Create2(struct PyModuleDef*, int apiver);

/* longobject.h */
PyObject *PyLong_FromLong(long);

/* end of Python headers */

int ts_isolate(const char *profiles);

static PyObject *
py_ts_isolate(PyObject *self, PyObject *args)
{
    const char *profiles;
    int result;

    if (!PyArg_ParseTuple(args, "s", &profiles))
        return NULL;

    return PyLong_FromLong(ts_isolate(profiles));
}

static PyMethodDef METHODS[] = {
    {"isolate", py_ts_isolate, METH_VARARGS, "Isolate the current process."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef MODULE = {
    1, NULL, NULL, 0, NULL,
    "py_ts_isolate",
    NULL,
    -1,
    METHODS,
};

PyObject *
PyInit_py_ts_isolate(void)
{
    return PyModule_Create2(&MODULE, 3);
}
