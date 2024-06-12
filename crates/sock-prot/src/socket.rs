use std::future::Future;
use std::io;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use crate::{AsNativeSocket, NativeSocket, Protector};

pub struct Socket<T, P: Protector + ?Sized> {
    socket: T,
    guard: SocketGuard<P>,
}

struct SocketGuard<P: Protector + ?Sized> {
    socket: NativeSocket,
    protector: Arc<P>,
}

impl<T: AsNativeSocket, P: Protector + ?Sized> Socket<T, P> {
    pub fn external(socket: T, protector: Arc<P>) -> io::Result<Self> {
        unsafe { protector.make_external(socket.as_native_socket())? }
        Ok(Self::new(socket, protector))
    }

    pub fn internal(socket: T, protector: Arc<P>) -> io::Result<Self> {
        unsafe { protector.make_internal(socket.as_native_socket())? }
        Ok(Self::new(socket, protector))
    }

    fn new(socket: T, protector: Arc<P>) -> Self {
        Self {
            guard: SocketGuard {
                socket: socket.as_native_socket(),
                protector,
            },
            socket,
        }
    }
}

impl<T, P: Protector + ?Sized> Socket<T, P> {
    pub async fn async_map<Fut, U>(self, fun: impl FnOnce(T) -> Fut) -> io::Result<Socket<U, P>>
    where
        Fut: Future<Output = io::Result<U>>,
    {
        let Self { guard, socket } = self;
        let socket = fun(socket).await?;
        Ok(Socket { socket, guard })
    }

    pub fn map<U>(self, fun: impl FnOnce(T) -> io::Result<U>) -> io::Result<Socket<U, P>> {
        let Self { guard, socket } = self;
        let socket = fun(socket)?;
        Ok(Socket { socket, guard })
    }
}

impl<T, P: Protector + ?Sized> Deref for Socket<T, P> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.socket
    }
}

impl<T, P: Protector + ?Sized> DerefMut for Socket<T, P> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.socket
    }
}

impl<P: Protector + ?Sized> Drop for SocketGuard<P> {
    fn drop(&mut self) {
        unsafe { self.protector.clean(self.socket) }
    }
}
