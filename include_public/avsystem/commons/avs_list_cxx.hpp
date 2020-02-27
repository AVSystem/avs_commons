/*
 * Copyright 2017-2020 AVSystem <avsystem@avsystem.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef AVS_COMMONS_LIST_CXX_H
#define AVS_COMMONS_LIST_CXX_H

#include <iterator>

#include <avsystem/commons/avs_list.h>

/**
 * @file avs_list_cxx.hpp
 *
 * A C++ wrapper over @ref AVS_LIST macro.
 *
 * <example>
 * @code
 * #include <stdio.h>
 * #include <string>
 * #include <avsystem/commons/avs_list_cxx.hpp>
 *
 * struct MyStruct {
 *     int index;
 *     std::string string;
 * };
 *
 * int main() {
 *    // declare a list - just like that!
 *    avs::List<MyStruct> list;
 *
 *    // let's fill it!
 *    for (int i = 0; i < 10; ++i) {
 *        MyStruct element;
 *        element.index = i;
 *        element.string = "This is list element " + std::to_string(i);
 *        list.push_back(element);
 *    }
 *
 *    // print the contents
 *    for (avs::ListIterator<MyStruct> it = list.begin(); it != list.end(); it++) {
 *        printf("%d -- %s\n", it->index, it->string.c_str());
 *    }
 * }
 * @endcode
 *
 * Another starting point for examples might be the testing code
 * (<c>test_list_cxx.cpp</c>).
 * </example>
 */

namespace avs {

namespace detail {

template <typename T>
class ListBase;

} // namespace detail

template <typename T>
class List;

template <typename T>
class ListIterator : public std::iterator<std::forward_iterator_tag, T> {
    template <typename U>
    friend class detail::ListBase;
    friend class List<T>;
    AVS_LIST(T) *entry_ptr_;

    ListIterator(AVS_LIST(T) *entry_ptr) : entry_ptr_(entry_ptr) {}

    bool is_null() const {
        return !entry_ptr_ || !*entry_ptr_;
    }

public:
    typedef T value_type;
    typedef ptrdiff_t difference_type;
    typedef T &reference;
    typedef T *pointer;
    typedef std::forward_iterator_tag iterator_category;

    ListIterator() : entry_ptr_(NULL) {}

    T &operator*() {
        return **entry_ptr_;
    }

    T *operator->() {
        return *entry_ptr_;
    }

    ListIterator<T> &operator++() {
        entry_ptr_ = reinterpret_cast<AVS_LIST(T) *>(
                reinterpret_cast<void *>(AVS_LIST_NEXT_PTR(entry_ptr_)));
        return *this;
    }

    ListIterator<T> operator++(int) {
        ListIterator<T> copy = *this;
        ++*this;
        return copy;
    }

    bool operator==(const ListIterator<T> &other) {
        if (is_null() && other.is_null()) {
            return true;
        }
        return entry_ptr_ == other.entry_ptr_;
    }

    bool operator!=(const ListIterator<T> &other) {
        return !(*this == other);
    }
};

namespace detail {

/** Minimal STL-style abstraction over @ref AVS_LIST - base class */
template <typename T>
class ListBase {
protected:
    AVS_LIST(T) backend_;

    ListBase(AVS_LIST(T) backend) : backend_(backend) {}

    ~ListBase() {}

public:
    typedef T value_type;
    typedef std::ptrdiff_t difference_type;
    typedef T &reference;
    typedef const T &const_reference;
    typedef T *pointer;
    typedef const T *const_pointer;
    typedef ListIterator<T> iterator;
    typedef ListIterator<const T> const_iterator;

    bool empty() const {
        return !backend_;
    }

    ListIterator<T> begin() {
        return ListIterator<T>(&backend_);
    }

    ListIterator<const T> begin() const {
        return ListIterator<const T>(
                const_cast<AVS_LIST(const T) *>(&backend_));
    }

    ListIterator<const T> cbegin() const {
        return ListIterator<const T>(
                const_cast<AVS_LIST(const T) *>(&backend_));
    }

    ListIterator<T> end() {
        return ListIterator<T>();
    }

    ListIterator<const T> end() const {
        return ListIterator<const T>();
    }

    ListIterator<const T> cend() const {
        return ListIterator<const T>();
    }
};

} // namespace detail

/**
 * STL-style view over pre-existing @ref AVS_LIST
 *
 * Does not support modifying operations
 */
template <typename T>
class ListView : public detail::ListBase<T> {
public:
    ListView(AVS_LIST(T) backend) : detail::ListBase<T>(backend) {}
};

/** Self-owning container based on @ref AVS_LIST */
template <typename T>
class List : public detail::ListBase<T> {
    AVS_LIST(T) *past_end_;

    List(const List<T> &);
    List<T> &operator=(const List<T> &);

public:
    List() : detail::ListBase<T>(NULL), past_end_(&this->backend_) {}

    ~List() {
        clear();
    }

    ListIterator<T> allocate(ListIterator<T> pos, size_t size = sizeof(T)) {
        AVS_LIST(T) element =
                reinterpret_cast<AVS_LIST(T)>(AVS_LIST_NEW_BUFFER(size));
        if (!element) {
            return this->end();
        }
        if (!pos.entry_ptr_) {
            pos.entry_ptr_ = past_end_;
        }
        AVS_LIST_INSERT(pos.entry_ptr_, element);
        if (pos.entry_ptr_ == past_end_) {
            past_end_ = reinterpret_cast<AVS_LIST(T) *>(
                    AVS_LIST_APPEND_PTR(pos.entry_ptr_));
        }
        return pos;
    }

#if __cplusplus >= 201103L
    template <typename... Args>
    ListIterator<T> emplace(ListIterator<T> pos, Args &&... args) {
        ListIterator<T> result = allocate(pos);
        if (result != this->end()) {
            new (&*result) T(std::forward<Args>(args)...);
        }
        return result;
    }

    template <typename... Args>
    ListIterator<T> emplace_back(Args &&... args) {
        return emplace(this->end(), std::forward<Args>(args)...);
    }
#endif

    ListIterator<T> insert(ListIterator<T> pos, const T &value) {
        ListIterator<T> result = allocate(pos);
        if (result != this->end()) {
            new (&*result) T(value);
        }
        return result;
    }

    ListIterator<T> push_back(const T &value) {
        return insert(this->end(), value);
    }

    ListIterator<T> erase(ListIterator<T> it) {
        it->~T();
        if (past_end_
                == reinterpret_cast<AVS_LIST(T) *>(
                           AVS_LIST_NEXT_PTR(it.entry_ptr_))) {
            past_end_ = it.entry_ptr_;
        }
        AVS_LIST_DELETE(it.entry_ptr_);
        // note that after AVS_LIST_DELETE(it.entry_ptr_), *it.entry_ptr_ will
        // point at the element that was after the deleted one
        return it;
    }

    void clear() {
        while (this->backend_) {
            erase(this->begin());
        }
    }

    operator ListView<const T>() const {
        return ListView<const T>(&*this->begin());
    }
};

} // namespace avs

#endif /* AVS_COMMONS_LIST_CXX_H */
