/*
 *   Copyright(C) 2011-2018 Intel Corporation All Rights Reserved.
 *
 *   The source code, information  and  material ("Material") contained herein is
 *   owned  by Intel Corporation or its suppliers or licensors, and title to such
 *   Material remains  with Intel Corporation  or its suppliers or licensors. The
 *   Material  contains proprietary information  of  Intel or  its  suppliers and
 *   licensors. The  Material is protected by worldwide copyright laws and treaty
 *   provisions. No  part  of  the  Material  may  be  used,  copied, reproduced,
 *   modified, published, uploaded, posted, transmitted, distributed or disclosed
 *   in any way  without Intel's  prior  express written  permission. No  license
 *   under  any patent, copyright  or  other intellectual property rights  in the
 *   Material  is  granted  to  or  conferred  upon  you,  either  expressly,  by
 *   implication, inducement,  estoppel or  otherwise.  Any  license  under  such
 *   intellectual  property  rights must  be express  and  approved  by  Intel in
 *   writing.
 *
 *   *Third Party trademarks are the property of their respective owners.
 *
 *   Unless otherwise  agreed  by Intel  in writing, you may not remove  or alter
 *   this  notice or  any other notice embedded  in Materials by Intel or Intel's
 *   suppliers or licensors in any way.
 *
 */

/* This file implement lock guard */

#ifndef SE_LOCK_HPP
#define SE_LOCK_HPP


#include "se_thread.h"
#include "uncopyable.h"

class Mutex: private Uncopyable
{
public:
    Mutex(){se_mutex_init(&m_mutex);}
    ~Mutex(){se_mutex_destroy(&m_mutex);}
    void lock(){se_mutex_lock(&m_mutex);}
    void unlock(){se_mutex_unlock(&m_mutex);}
private:
    se_mutex_t m_mutex;
};

class LockGuard: private Uncopyable
{
public:
    LockGuard(Mutex* mutex):m_mutex(mutex){m_mutex->lock();}
    ~LockGuard(){m_mutex->unlock();}
private:
    Mutex* m_mutex;
};

#endif
